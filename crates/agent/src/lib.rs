pub mod forwarder;
pub mod status;
pub mod tunnel;

use tokio::sync::{oneshot, watch};
use tracing::info;

pub use detour_core::AgentConfig;

use detour_core::{DetourError, ServiceRoute, SessionId, TunnelStatus};

struct TunnelHandle {
    session_id:  SessionId,
    route:       ServiceRoute,
    status_rx:   watch::Receiver<TunnelStatus>,
    shutdown_tx: oneshot::Sender<()>,
    task:        tokio::task::JoinHandle<()>,
}

pub struct AgentHandle {
    tunnels:       Vec<TunnelHandle>,
    status_server: tokio::task::JoinHandle<()>,
}

fn status_rank(s: &TunnelStatus) -> u8 {
    match s {
        TunnelStatus::Connected    => 0,
        TunnelStatus::Reconnecting => 1,
        TunnelStatus::Connecting   => 2,
        TunnelStatus::Error(_)     => 3,
        TunnelStatus::Stopped      => 4,
    }
}

impl AgentHandle {
    pub async fn start(config: detour_core::AgentConfig) -> Result<Self, DetourError> {
        if config.routes.is_empty() {
            return Err(DetourError::ConfigError("no routes specified".into()));
        }

        let mut tunnels      = Vec::new();
        let mut status_entries = Vec::new();

        for route in &config.routes {
            let session_id = SessionId::new();
            let (status_tx, status_rx) = watch::channel(TunnelStatus::Connecting);
            let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();

            let broker_url    = config.broker_url.clone();
            let auth_mode     = config.auth_mode.clone();
            let route_clone   = route.clone();
            let session_clone = session_id.clone();
            let tx_clone      = status_tx.clone();

            let task = tokio::spawn(async move {
                tunnel::run(broker_url, auth_mode, route_clone, session_clone, tx_clone, shutdown_rx).await;
            });

            status_entries.push((session_id.clone(), route.clone(), status_rx.clone()));

            tunnels.push(TunnelHandle {
                session_id,
                route: route.clone(),
                status_rx,
                shutdown_tx,
                task,
            });

            // status_tx held alive via tx_clone inside the spawned task
            drop(status_tx);
        }

        let broker_url = config.broker_url.clone();
        let status_server = tokio::spawn(async move {
            status::serve(status_entries, broker_url).await;
        });

        info!(routes = config.routes.len(), "agent started");

        Ok(Self { tunnels, status_server })
    }

    pub fn sessions(&self) -> Vec<(String, SessionId)> {
        self.tunnels.iter()
            .map(|t| (t.route.service_name.clone(), t.session_id.clone()))
            .collect()
    }

    pub fn status(&self) -> TunnelStatus {
        self.tunnels.iter()
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
        info!("agent stopped");
        Ok(())
    }
}
