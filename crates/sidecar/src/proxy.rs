use std::sync::Arc;

use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tonic::transport::Channel;
use tracing::{info, warn};

use detour_proto::detour::detour_client::DetourClient;

use crate::inspector::SessionResolver;
use crate::raw;

#[derive(Clone)]
pub struct ProxyState {
    pub resolver: Arc<dyn SessionResolver>,
    pub app_upstream: String,
    pub broker_client: DetourClient<Channel>,
    pub service_name: String,
    pub log_routed: bool,
}

const HEALTHZ_OK: &[u8] =
    b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok";

/// Handle a freshly accepted connection at the byte level (US-004/US-005).
///
/// Only the HTTP request head is sniffed — just enough to read `X-Route-To` and
/// answer health checks. Everything else is moved as raw bytes: routed
/// connections over the broker raw data plane, others spliced to the local app.
pub async fn handle_conn(mut sock: TcpStream, state: ProxyState) {
    let (head, rest) = match raw::sniff_head(&mut sock).await {
        Ok(Ok(parsed)) => parsed,
        Ok(Err(raw_bytes)) => {
            // Not an HTTP/1.x head (e.g. an HTTP/2 preface) — splice verbatim.
            if let Err(e) = raw::splice_upstream(sock, &state.app_upstream, raw_bytes).await {
                warn!(error = %e, "raw splice to upstream failed");
            }
            return;
        }
        Err(e) => {
            warn!(error = %e, "failed to read request head");
            return;
        }
    };

    if head.path == "/healthz" {
        let _ = sock.write_all(HEALTHZ_OK).await;
        return;
    }

    // Protocol upgrades (WebSocket, h2c, etc.) must never be buffered or
    // HTTP-parsed past the handshake; the raw data plane handles them as opaque
    // byte streams (US-005). We only sniffed the head, so this already holds —
    // detect it explicitly for logging and to assert the invariant.
    let upgrade = raw::is_upgrade(&head.headers);

    // Replay the bytes already read off the socket downstream so nothing is lost.
    let mut initial = head.raw;
    initial.extend_from_slice(&rest);

    match state.resolver.resolve(&head.headers).await {
        Some(record) => {
            if state.log_routed {
                info!(
                    session_id = %record.session_id,
                    method     = %head.method,
                    path       = %head.path,
                    upgrade,
                    "routing to local over raw data plane"
                );
            }

            let connection_id = uuid::Uuid::new_v4().to_string();
            if let Err(e) = raw::relay_raw(
                state.broker_client.clone(),
                record.session_id.to_string(),
                connection_id,
                state.service_name.clone(),
                initial,
                sock,
            )
            .await
            {
                // Once a routed connection has begun streaming to the broker,
                // falling back to the upstream is unsafe (US-010); fail closed.
                warn!(error = %e, "routed raw relay failed; no upstream fallback");
            }
        }
        None => {
            if let Err(e) = raw::splice_upstream(sock, &state.app_upstream, initial).await {
                warn!(error = %e, "raw splice to upstream failed");
            }
        }
    }
}
