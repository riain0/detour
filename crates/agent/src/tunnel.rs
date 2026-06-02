use std::collections::HashMap;
use std::time::Duration;

use bytes::Bytes;
use tokio::sync::{oneshot, watch};
use tokio_stream::wrappers::ReceiverStream;
use tonic::metadata::MetadataValue;
use tonic::transport::{Channel, ClientTlsConfig};
use tonic::Request;
use tracing::{info, warn};

use detour_core::{AuthMode, ServiceRoute, SessionId, TunnelStatus};
use detour_proto::detour::{
    agent_message, broker_message, detour_client::DetourClient, AgentMessage, Heartbeat,
    RawConnFrame, RegisterSession, RouteEntry,
};

const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(30);
const RECONNECT_DELAY: Duration = Duration::from_secs(3);
const MAX_RECONNECT_DELAY: Duration = Duration::from_secs(60);

pub async fn run(
    broker_url: String,
    auth_mode: AuthMode,
    auth_token: Option<String>,
    routes: Vec<ServiceRoute>,
    session_id: SessionId,
    status_tx: watch::Sender<TunnelStatus>,
    shutdown_rx: oneshot::Receiver<()>,
) {
    let mut shutdown_rx = Some(shutdown_rx);
    let mut delay = RECONNECT_DELAY;

    loop {
        let _ = status_tx.send(TunnelStatus::Connecting);

        match connect_and_run(
            &broker_url,
            &auth_mode,
            auth_token.as_deref(),
            &routes,
            &session_id,
            &status_tx,
        )
        .await
        {
            Ok(()) => {
                let _ = status_tx.send(TunnelStatus::Stopped);
                return;
            }
            Err(e) => {
                warn!(error = %e, "tunnel disconnected, reconnecting in {:?}", delay);
                let _ = status_tx.send(TunnelStatus::Reconnecting);
            }
        }

        tokio::select! {
            _ = tokio::time::sleep(delay) => {}
            _ = async { if let Some(rx) = shutdown_rx.take() { let _ = rx.await; } } => {
                let _ = status_tx.send(TunnelStatus::Stopped);
                return;
            }
        }

        delay = (delay * 2).min(MAX_RECONNECT_DELAY);
    }
}

async fn connect_and_run(
    broker_url: &str,
    auth_mode: &AuthMode,
    auth_token: Option<&str>,
    routes: &[ServiceRoute],
    session_id: &SessionId,
    status_tx: &watch::Sender<TunnelStatus>,
) -> anyhow::Result<()> {
    info!(broker_url = %broker_url, "connecting to broker");
    let mut endpoint = Channel::from_shared(broker_url.to_string())?;
    if broker_url.starts_with("https://") {
        endpoint = endpoint.tls_config(ClientTlsConfig::new().with_webpki_roots())?;
    }
    let channel = endpoint.connect().await.map_err(|e| {
        warn!(error = %e, broker_url = %broker_url, "failed to connect to broker");
        e
    })?;
    info!("broker channel established");

    let mut client = DetourClient::new(channel);

    let (tx, rx) = tokio::sync::mpsc::channel::<AgentMessage>(64);

    let proto_routes: Vec<RouteEntry> = routes
        .iter()
        .map(|r| RouteEntry {
            service_name: r.service_name.clone(),
            local_port: r.local_port as u32,
        })
        .collect();

    tx.send(AgentMessage {
        payload: Some(agent_message::Payload::Register(RegisterSession {
            session_id: session_id.to_string(),
            auth_mode: auth_mode.to_string(),
            routes: proto_routes,
        })),
    })
    .await?;

    let mut request = Request::new(ReceiverStream::new(rx));
    attach_auth_metadata(&mut request, auth_mode, auth_token)?;
    let response = client.open_tunnel(request).await.map_err(|e| {
        warn!(error = %e, "open_tunnel RPC failed");
        e
    })?;
    let mut inbound = response.into_inner();

    let _ = status_tx.send(TunnelStatus::Connected);
    info!(session_id = %session_id, "tunnel connected");

    // Build service_name → local_port map for request dispatch
    let route_map: HashMap<String, u16> = routes
        .iter()
        .map(|r| (r.service_name.clone(), r.local_port))
        .collect();
    let mut inflight_requests: HashMap<String, tokio::sync::mpsc::Sender<Bytes>> = HashMap::new();
    // Active raw connections keyed by connection_id → channel feeding broker
    // frames to the per-connection forwarder task (US-003).
    let mut inflight_connections: HashMap<String, tokio::sync::mpsc::Sender<RawConnFrame>> =
        HashMap::new();

    let session_id_str = session_id.to_string();
    let tx_hb = tx.clone();
    let heartbeat = tokio::spawn(async move {
        let mut interval = tokio::time::interval(HEARTBEAT_INTERVAL);
        interval.tick().await;
        loop {
            interval.tick().await;
            let msg = AgentMessage {
                payload: Some(agent_message::Payload::Heartbeat(Heartbeat {
                    session_id: session_id_str.clone(),
                })),
            };
            if tx_hb.send(msg).await.is_err() {
                break;
            }
        }
    });

    while let Some(msg) = inbound.message().await? {
        match msg.payload {
            Some(broker_message::Payload::Ack(ack)) => {
                info!(session_id = %ack.session_id, ttl = ack.ttl, "session acknowledged");
            }
            Some(broker_message::Payload::Request(req)) => {
                if let Some(body_tx) = inflight_requests.get(&req.request_id).cloned() {
                    if !req.body_chunk.is_empty()
                        && body_tx.send(Bytes::from(req.body_chunk.clone())).await.is_err()
                    {
                        inflight_requests.remove(&req.request_id);
                    }
                    if req.end_of_body {
                        inflight_requests.remove(&req.request_id);
                    }
                    continue;
                }

                let local_port = match route_map.get(&req.service_name) {
                    Some(&p) => p,
                    None => {
                        warn!(service = %req.service_name, "no route for service, dropping request");
                        continue;
                    }
                };
                let (body_tx, body_rx) = tokio::sync::mpsc::channel::<Bytes>(16);
                if !req.body_chunk.is_empty()
                    && body_tx.send(Bytes::from(req.body_chunk.clone())).await.is_err()
                {
                    continue;
                }
                if !req.end_of_body {
                    inflight_requests.insert(req.request_id.clone(), body_tx);
                }

                let tx_resp = tx.clone();
                tokio::spawn(async move {
                    crate::forwarder::forward(req, local_port, tx_resp, body_rx).await;
                });
            }
            // Raw per-connection byte stream from the broker (US-003).
            Some(broker_message::Payload::Raw(frame)) => {
                let connection_id = frame.connection_id.clone();

                // Continuation frame for an already-open connection.
                if let Some(conn_tx) = inflight_connections.get(&connection_id).cloned() {
                    let is_eof = frame.is_eof;
                    if conn_tx.send(frame).await.is_err() || is_eof {
                        inflight_connections.remove(&connection_id);
                    }
                    continue;
                }

                // Opening frame: dial the routed upstream and start pumping.
                let local_port = match route_map.get(&frame.service_name) {
                    Some(&p) => p,
                    None => {
                        warn!(service = %frame.service_name, "no route for service, dropping connection");
                        continue;
                    }
                };

                let (conn_tx, conn_rx) = tokio::sync::mpsc::channel::<RawConnFrame>(16);
                if !frame.is_eof {
                    inflight_connections.insert(connection_id, conn_tx);
                }

                let tx_raw = tx.clone();
                tokio::spawn(async move {
                    crate::forwarder::forward_connection(frame, local_port, tx_raw, conn_rx).await;
                });
            }
            None => {}
        }
    }

    heartbeat.abort();
    Ok(())
}

fn attach_auth_metadata(
    request: &mut Request<ReceiverStream<AgentMessage>>,
    auth_mode: &AuthMode,
    auth_token: Option<&str>,
) -> anyhow::Result<()> {
    if !matches!(auth_mode, AuthMode::SessionId) {
        let token = auth_token.ok_or_else(|| anyhow::anyhow!("missing auth token for {}", auth_mode))?;
        let value = MetadataValue::try_from(format!("Bearer {}", token))?;
        request.metadata_mut().insert("authorization", value);
    }

    Ok(())
}
