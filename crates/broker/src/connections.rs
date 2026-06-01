use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{mpsc, Mutex};

use detour_core::SessionId;
use detour_proto::detour::{BrokerMessage, RawConnFrame, RelayResponse, RelayResponseMsg};

pub type TunnelTx = mpsc::Sender<Result<BrokerMessage, tonic::Status>>;

pub type PendingTx = mpsc::Sender<Result<RelayResponseMsg, tonic::Status>>;

pub type RawConnTx = mpsc::Sender<Result<RawConnFrame, tonic::Status>>;

struct PendingEntry {
    tx: PendingTx,
    saw_first_response: bool,
}

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
        self.inner
            .lock()
            .await
            .get(&session_id.to_string())
            .cloned()
    }
}

/// Tracks in-flight relayed requests, keyed by request_id.
/// relay_request inserts a sender; open_tunnel fires it when the agent responds.
#[derive(Default, Clone)]
pub struct PendingRequests {
    inner: Arc<Mutex<HashMap<String, PendingEntry>>>,
}

impl PendingRequests {
    /// Register a new in-flight request. Returns the broker request_id.
    pub async fn register(&self, tx: PendingTx) -> String {
        let request_id = uuid::Uuid::new_v4().to_string();
        self.inner.lock().await.insert(
            request_id.clone(),
            PendingEntry {
                tx,
                saw_first_response: false,
            },
        );
        request_id
    }

    /// Called by open_tunnel when the agent sends a RelayResponse. Returns true
    /// if a waiter was found and notified.
    pub async fn push(&self, response: RelayResponse) -> bool {
        let request_id = response.request_id.clone();
        let end_of_body = response.end_of_body;
        let message = RelayResponseMsg {
            request_id: response.request_id,
            status_code: response.status_code,
            headers: response.headers,
            body_chunk: response.body_chunk,
            end_of_body,
        };

        let tx = {
            let mut map = self.inner.lock().await;
            let Some(entry) = map.get_mut(&request_id) else {
                return false;
            };
            entry.saw_first_response = true;
            let tx = entry.tx.clone();
            if end_of_body {
                map.remove(&request_id);
            }
            tx
        };

        tx.send(Ok(message)).await.is_ok()
    }

    pub async fn timeout_unstarted(&self, request_id: &str) -> bool {
        let mut map = self.inner.lock().await;
        let Some(entry) = map.get(request_id) else {
            return false;
        };
        if entry.saw_first_response {
            return false;
        }

        let entry = map.remove(request_id).expect("pending request exists");
        let _ = entry
            .tx
            .send(Err(tonic::Status::deadline_exceeded("agent relay timeout")))
            .await;
        true
    }

    pub async fn remove(&self, request_id: &str) {
        self.inner.lock().await.remove(request_id);
    }
}

/// Tracks active raw connections, keyed by connection_id.
/// relay_connection registers a sender for the sidecar's response stream;
/// open_tunnel delivers the agent's raw frames to it as they arrive.
#[derive(Default, Clone)]
pub struct RawConnections {
    inner: Arc<Mutex<HashMap<String, RawConnTx>>>,
}

impl RawConnections {
    /// Register the sidecar response stream for a connection.
    pub async fn register(&self, connection_id: &str, tx: RawConnTx) {
        self.inner
            .lock()
            .await
            .insert(connection_id.to_string(), tx);
    }

    pub async fn remove(&self, connection_id: &str) {
        self.inner.lock().await.remove(connection_id);
    }

    /// Deliver an agent frame to the waiting sidecar stream. Returns true if a
    /// waiter was found and notified. The entry is dropped once the frame closes
    /// the connection half (is_eof) or the sidecar stream is gone.
    pub async fn deliver(&self, frame: RawConnFrame) -> bool {
        let connection_id = frame.connection_id.clone();
        let is_eof = frame.is_eof;

        let tx = {
            let map = self.inner.lock().await;
            match map.get(&connection_id) {
                Some(tx) => tx.clone(),
                None => return false,
            }
        };

        let ok = tx.send(Ok(frame)).await.is_ok();
        if is_eof || !ok {
            self.inner.lock().await.remove(&connection_id);
        }
        ok
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn pending_requests_stream_multiple_chunks_until_eof() {
        let pending = PendingRequests::default();
        let (tx, mut rx) = mpsc::channel(4);
        let request_id = pending.register(tx).await;

        assert!(pending
            .push(RelayResponse {
                request_id: request_id.clone(),
                status_code: 200,
                headers: vec![],
                body_chunk: b"hello".to_vec(),
                end_of_body: false,
            })
            .await);
        assert!(pending
            .push(RelayResponse {
                request_id: request_id.clone(),
                status_code: 200,
                headers: vec![],
                body_chunk: b" world".to_vec(),
                end_of_body: true,
            })
            .await);

        let first = rx.recv().await.expect("first chunk").expect("ok result");
        assert_eq!(first.request_id, request_id);
        assert_eq!(first.body_chunk, b"hello");
        assert!(!first.end_of_body);

        let second = rx.recv().await.expect("second chunk").expect("ok result");
        assert_eq!(second.body_chunk, b" world");
        assert!(second.end_of_body);

        assert!(!pending
            .push(RelayResponse {
                request_id,
                status_code: 200,
                headers: vec![],
                body_chunk: Vec::new(),
                end_of_body: true,
            })
            .await);
    }

    #[tokio::test]
    async fn pending_requests_timeout_only_before_first_response() {
        let pending = PendingRequests::default();

        let (tx, mut rx) = mpsc::channel(1);
        let request_id = pending.register(tx).await;
        assert!(pending.timeout_unstarted(&request_id).await);
        let timed_out = rx.recv().await.expect("timeout result");
        assert!(timed_out.is_err());

        let (tx, _rx) = mpsc::channel(1);
        let request_id = pending.register(tx).await;
        assert!(pending
            .push(RelayResponse {
                request_id: request_id.clone(),
                status_code: 200,
                headers: vec![],
                body_chunk: b"chunk".to_vec(),
                end_of_body: false,
            })
            .await);
        assert!(!pending.timeout_unstarted(&request_id).await);
    }

    #[tokio::test]
    async fn raw_connections_deliver_in_order_until_eof() {
        let raw = RawConnections::default();
        let (tx, mut rx) = mpsc::channel(4);
        raw.register("conn-1", tx).await;

        assert!(raw
            .deliver(RawConnFrame {
                session_id: "s".into(),
                connection_id: "conn-1".into(),
                payload: b"hello".to_vec(),
                is_eof: false,
                service_name: String::new(),
            })
            .await);
        assert!(raw
            .deliver(RawConnFrame {
                session_id: "s".into(),
                connection_id: "conn-1".into(),
                payload: b" world".to_vec(),
                is_eof: true,
                service_name: String::new(),
            })
            .await);

        let first = rx.recv().await.expect("first").expect("ok");
        assert_eq!(first.payload, b"hello");
        assert!(!first.is_eof);
        let second = rx.recv().await.expect("second").expect("ok");
        assert_eq!(second.payload, b" world");
        assert!(second.is_eof);

        // eof dropped the entry; further delivery finds no waiter.
        assert!(!raw
            .deliver(RawConnFrame {
                session_id: "s".into(),
                connection_id: "conn-1".into(),
                payload: Vec::new(),
                is_eof: false,
                service_name: String::new(),
            })
            .await);
    }

    #[tokio::test]
    async fn raw_connections_deliver_unknown_connection_returns_false() {
        let raw = RawConnections::default();
        assert!(!raw
            .deliver(RawConnFrame {
                session_id: "s".into(),
                connection_id: "missing".into(),
                payload: b"x".to_vec(),
                is_eof: false,
                service_name: String::new(),
            })
            .await);
    }
}
