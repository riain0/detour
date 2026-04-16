use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{mpsc, oneshot, Mutex};

use detour_core::SessionId;
use detour_proto::detour::{BrokerMessage, RelayResponse};

pub type TunnelTx = mpsc::Sender<Result<BrokerMessage, tonic::Status>>;

/// Sender half of a per-request rendezvous. The relay_request handler parks
/// one of these per in-flight request; open_tunnel fires it when the agent
/// sends its RelayResponse back.
pub type PendingTx = oneshot::Sender<RelayResponse>;

#[derive(Default, Clone)]
pub struct ConnectionMap {
    inner: Arc<Mutex<HashMap<String, TunnelTx>>>,
}

impl ConnectionMap {
    pub async fn insert(&self, session_id: &SessionId, tx: TunnelTx) {
        self.inner.lock().await.insert(session_id.to_string(), tx);
    }

    pub async fn remove(&self, session_id: &SessionId) {
        self.inner.lock().await.remove(&session_id.to_string());
    }

    pub async fn get(&self, session_id: &SessionId) -> Option<TunnelTx> {
        self.inner.lock().await.get(&session_id.to_string()).cloned()
    }
}

/// Tracks in-flight relayed requests, keyed by request_id.
/// relay_request inserts a sender; open_tunnel fires it when the agent responds.
#[derive(Default, Clone)]
pub struct PendingRequests {
    inner: Arc<Mutex<HashMap<String, PendingTx>>>,
}

impl PendingRequests {
    /// Register a new in-flight request. Returns the request_id and the receiver
    /// that relay_request should await on.
    pub async fn register(&self, tx: PendingTx) -> String {
        let request_id = uuid::Uuid::new_v4().to_string();
        self.inner.lock().await.insert(request_id.clone(), tx);
        request_id
    }

    /// Called by open_tunnel when the agent sends a RelayResponse. Returns true
    /// if a waiter was found and notified.
    pub async fn complete(&self, response: RelayResponse) -> bool {
        let mut map = self.inner.lock().await;
        if let Some(tx) = map.remove(&response.request_id) {
            let _ = tx.send(response);
            true
        } else {
            false
        }
    }

    pub async fn remove(&self, request_id: &str) {
        self.inner.lock().await.remove(request_id);
    }
}
