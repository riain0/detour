pub mod forwarder;
pub mod outbound;
pub mod status;
pub mod tunnel;

use tokio::sync::{oneshot, watch};
use tracing::info;

pub use detour_core::AgentConfig;

use detour_core::{DetourError, ServiceRoute, SessionId, TunnelStatus};

struct TunnelHandle {
    session_id: SessionId,
    routes: Vec<ServiceRoute>,
    status_rx: watch::Receiver<TunnelStatus>,
    shutdown_tx: oneshot::Sender<()>,
    task: tokio::task::JoinHandle<()>,
}

pub struct AgentHandle {
    tunnels: Vec<TunnelHandle>,
    status_server: tokio::task::JoinHandle<()>,
    outbound_server: tokio::task::JoinHandle<()>,
}

fn status_rank(s: &TunnelStatus) -> u8 {
    match s {
        TunnelStatus::Connected => 0,
        TunnelStatus::Reconnecting => 1,
        TunnelStatus::Connecting => 2,
        TunnelStatus::Error(_) => 3,
        TunnelStatus::Stopped => 4,
    }
}

impl AgentHandle {
    pub async fn start(config: detour_core::AgentConfig) -> Result<Self, DetourError> {
        if config.routes.is_empty() {
            return Err(DetourError::ConfigError("no routes specified".into()));
        }

        let session_id = SessionId::new();
        let (status_tx, status_rx) = watch::channel(TunnelStatus::Connecting);
        let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();

        let broker_url = config.broker_url.clone();
        let auth_mode = config.auth_mode.clone();
        let routes_clone = config.routes.clone();
        let session_clone = session_id.clone();
        let tx_clone = status_tx.clone();

        let task = tokio::spawn(async move {
            tunnel::run(
                broker_url,
                auth_mode,
                routes_clone,
                session_clone,
                tx_clone,
                shutdown_rx,
            )
            .await;
        });

        // One status entry per route — all share the same session_id and status_rx
        let status_entries: Vec<_> = config
            .routes
            .iter()
            .map(|r| (session_id.clone(), r.clone(), status_rx.clone()))
            .collect();

        let broker_url = config.broker_url.clone();
        let status_server = tokio::spawn(async move {
            status::serve(status_entries, broker_url).await;
        });

        let outbound_broker = config.broker_url.clone();
        let outbound_sid = session_id.clone();
        let outbound_port = config.socks5_port;
        let outbound_server = tokio::spawn(async move {
            outbound::serve(outbound_broker, outbound_sid, outbound_port).await;
        });

        // status_tx held alive via tx_clone inside the spawned task
        drop(status_tx);

        let routes = config.routes.clone();
        info!(routes = routes.len(), session_id = %session_id, socks5_port = outbound_port, "agent started");

        Ok(Self {
            tunnels: vec![TunnelHandle {
                session_id,
                routes,
                status_rx,
                shutdown_tx,
                task,
            }],
            status_server,
            outbound_server,
        })
    }

    /// Returns one (service_name, session_id) pair per route. All share the same session_id.
    pub fn sessions(&self) -> Vec<(String, SessionId)> {
        self.tunnels
            .iter()
            .flat_map(|t| {
                t.routes
                    .iter()
                    .map(|r| (r.service_name.clone(), t.session_id.clone()))
            })
            .collect()
    }

    pub fn status(&self) -> TunnelStatus {
        self.tunnels
            .iter()
            .map(|t| t.status_rx.borrow().clone())
            .max_by_key(status_rank)
            .unwrap_or(TunnelStatus::Stopped)
    }

    pub async fn stop(self) -> Result<(), DetourError> {
        for t in self.tunnels {
            let _ = t.shutdown_tx.send(());
            let _ = t.task.await;
        }
        self.status_server.abort();
        self.outbound_server.abort();
        info!("agent stopped");
        Ok(())
    }
}
