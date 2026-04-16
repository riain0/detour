use std::time::Duration;

use tokio::sync::{oneshot, watch};
use tokio_stream::wrappers::ReceiverStream;
use tonic::transport::{Channel, ClientTlsConfig};
use tracing::{info, warn};

use detour_core::{AuthMode, ServiceRoute, SessionId, TunnelStatus};
use detour_proto::detour::{
    agent_message, broker_message, detour_client::DetourClient, AgentMessage, Heartbeat,
    RegisterSession,
};

const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(30);
const RECONNECT_DELAY:    Duration = Duration::from_secs(3);
const MAX_RECONNECT_DELAY: Duration = Duration::from_secs(60);

pub async fn run(
    broker_url:  String,
    auth_mode:   AuthMode,
    route:       ServiceRoute,
    session_id:  SessionId,
    status_tx:   watch::Sender<TunnelStatus>,
    shutdown_rx: oneshot::Receiver<()>,
) {
    let mut shutdown_rx = Some(shutdown_rx);
    let mut delay = RECONNECT_DELAY;

    loop {
        let _ = status_tx.send(TunnelStatus::Connecting);

        match connect_and_run(&broker_url, &auth_mode, &route, &session_id, &status_tx).await {
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
    auth_mode:  &AuthMode,
    route:      &ServiceRoute,
    session_id: &SessionId,
    status_tx:  &watch::Sender<TunnelStatus>,
) -> anyhow::Result<()> {
    info!(broker_url = %broker_url, "connecting to broker");
    let mut endpoint = Channel::from_shared(broker_url.to_string())?;
    if broker_url.starts_with("https://") {
        endpoint = endpoint.tls_config(ClientTlsConfig::new().with_webpki_roots())?;
    }
    let channel = endpoint
        .connect()
        .await
        .map_err(|e| {
            warn!(error = %e, broker_url = %broker_url, "failed to connect to broker");
            e
        })?;
    info!("broker channel established");

    let mut client = DetourClient::new(channel);

    let (tx, rx) = tokio::sync::mpsc::channel::<AgentMessage>(64);

    tx.send(AgentMessage {
        payload: Some(agent_message::Payload::Register(RegisterSession {
            session_id:       session_id.to_string(),
            auth_mode:        auth_mode.to_string(),
            service_name:     route.service_name.clone(),
            allowed_services: vec![route.service_name.clone()],
        })),
    })
    .await?;

    let request_stream = ReceiverStream::new(rx);
    let response = client.open_tunnel(request_stream).await
        .map_err(|e| {
            warn!(error = %e, "open_tunnel RPC failed");
            e
        })?;
    let mut inbound = response.into_inner();

    let _ = status_tx.send(TunnelStatus::Connected);
    info!(session_id = %session_id, "tunnel connected");

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

    let local_port = route.local_port;
    while let Some(msg) = inbound.message().await? {
        match msg.payload {
            Some(broker_message::Payload::Ack(ack)) => {
                info!(session_id = %ack.session_id, ttl = ack.ttl, "session acknowledged");
            }
            Some(broker_message::Payload::Request(req)) => {
                let tx_resp = tx.clone();
                tokio::spawn(async move {
                    crate::forwarder::forward(req, local_port, tx_resp).await;
                });
            }
            None => {}
        }
    }

    heartbeat.abort();
    Ok(())
}
