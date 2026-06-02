use std::sync::Arc;

use http::HeaderMap;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tonic::transport::Channel;
use tracing::{info, warn};

use detour_proto::detour::detour_client::DetourClient;

use crate::inspector::{SessionResolver, ROUTE_HEADER};
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

/// Handle a freshly accepted connection at the byte level (US-004/US-005/US-006).
///
/// Only the request head is sniffed — for HTTP/1.x the text head, for HTTP/2 the
/// first HEADERS frame — just enough to read `X-Route-To` and answer health
/// checks. Everything else is moved as raw bytes: routed connections over the
/// broker raw data plane, others spliced to the local app.
pub async fn handle_conn(mut sock: TcpStream, state: ProxyState) {
    match raw::sniff_head(&mut sock).await {
        Ok(raw::Sniff::Http1 { head, rest }) => {
            if head.path == "/healthz" {
                let _ = sock.write_all(HEALTHZ_OK).await;
                return;
            }

            // Protocol upgrades (WebSocket, h2c, etc.) must never be buffered or
            // HTTP-parsed past the handshake; the raw data plane carries them as
            // opaque byte streams (US-005). Detected here only for logging.
            let upgrade = raw::is_upgrade(&head.headers);

            let mut initial = head.raw;
            initial.extend_from_slice(&rest);
            route_or_splice(
                state,
                &head.headers,
                &head.method,
                &head.path,
                upgrade,
                initial,
                sock,
            )
            .await;
        }

        // HTTP/2 (gRPC). Read frames to extract x-route-to from the first HEADERS
        // frame, then relay the whole connection raw — byte-transparent, so HTTP/2
        // framing and trailers are preserved end to end (US-006).
        Ok(raw::Sniff::Http2 { buffered }) => {
            let (route, buffered) = match raw::read_h2_route(&mut sock, buffered).await {
                Ok(v) => v,
                Err(e) => {
                    warn!(error = %e, "failed to read HTTP/2 head");
                    return;
                }
            };
            let mut headers = HeaderMap::new();
            if let Some(v) = route.as_deref().and_then(|v| v.parse().ok()) {
                headers.insert(ROUTE_HEADER, v);
            }
            route_or_splice(state, &headers, "HTTP/2", "*", false, buffered, sock).await;
        }

        Ok(raw::Sniff::Raw { buffered }) => {
            if let Err(e) = raw::splice_upstream(sock, &state.app_upstream, buffered).await {
                warn!(error = %e, "raw splice to upstream failed");
            }
        }

        Err(e) => warn!(error = %e, "failed to read request head"),
    }
}

/// Resolve the route from `headers`; relay over the raw data plane if a session
/// matches, otherwise splice to the local app. `initial` is replayed downstream.
async fn route_or_splice(
    state: ProxyState,
    headers: &HeaderMap,
    method: &str,
    path: &str,
    upgrade: bool,
    initial: Vec<u8>,
    sock: TcpStream,
) {
    match state.resolver.resolve(headers).await {
        Some(record) => {
            if state.log_routed {
                info!(
                    session_id = %record.session_id,
                    method,
                    path,
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
