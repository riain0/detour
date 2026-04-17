use axum::{extract::State, routing::get, Json, Router};
use serde_json::{json, Value};
use std::sync::Arc;
use tokio::sync::watch;
use tracing::{info, warn};

use detour_core::{ServiceRoute, SessionId, TunnelStatus};

const DEFAULT_STATUS_PORT: u16 = 29876;
const MAX_PORT_TRIES: u16 = 10;

#[derive(Clone)]
struct SessionEntry {
    session_id: SessionId,
    route: ServiceRoute,
    status_rx: watch::Receiver<TunnelStatus>,
}

#[derive(Clone)]
struct AppState {
    sessions: Arc<Vec<SessionEntry>>,
    broker_url: String,
}

pub async fn serve(
    sessions: Vec<(SessionId, ServiceRoute, watch::Receiver<TunnelStatus>)>,
    broker_url: String,
) {
    let entries: Vec<SessionEntry> = sessions
        .into_iter()
        .map(|(session_id, route, status_rx)| SessionEntry {
            session_id,
            route,
            status_rx,
        })
        .collect();

    let state = AppState {
        sessions: Arc::new(entries),
        broker_url,
    };

    let app = Router::new()
        .route("/status", get(status_handler))
        .with_state(state);

    let port = find_available_port().await;
    let addr = format!("127.0.0.1:{}", port);

    info!(port = port, "status endpoint listening");

    if port != DEFAULT_STATUS_PORT {
        let event = serde_json::json!({
            "event":       "status_port",
            "ts":          chrono_now(),
            "status_port": port,
        });
        println!("{}", event);
    }

    let listener = tokio::net::TcpListener::bind(&addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}

async fn status_handler(State(state): State<AppState>) -> Json<Value> {
    let sessions: Vec<Value> = state
        .sessions
        .iter()
        .map(|e| {
            let s = e.status_rx.borrow().clone();
            let status_str = status_label(&s);
            json!({
                "service":    e.route.service_name,
                "session_id": e.session_id.as_str(),
                "port":       e.route.local_port,
                "status":     status_str,
            })
        })
        .collect();

    let overall = state
        .sessions
        .iter()
        .map(|e| e.status_rx.borrow().clone())
        .max_by_key(status_rank)
        .unwrap_or(TunnelStatus::Stopped);

    Json(json!({
        "version":    "1",
        "status":     status_label(&overall),
        "broker_url": state.broker_url,
        "sessions":   sessions,
    }))
}

fn status_label(s: &TunnelStatus) -> &'static str {
    match s {
        TunnelStatus::Connecting => "connecting",
        TunnelStatus::Connected => "connected",
        TunnelStatus::Reconnecting => "reconnecting",
        TunnelStatus::Stopped => "stopped",
        TunnelStatus::Error(_) => "error",
    }
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

async fn find_available_port() -> u16 {
    for offset in 0..MAX_PORT_TRIES {
        let port = DEFAULT_STATUS_PORT + offset;
        if tokio::net::TcpListener::bind(format!("127.0.0.1:{}", port))
            .await
            .is_ok()
        {
            return port;
        }
    }
    warn!(
        "all status ports in use, defaulting to {}",
        DEFAULT_STATUS_PORT
    );
    DEFAULT_STATUS_PORT
}

fn chrono_now() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    format!("{}Z", secs)
}
