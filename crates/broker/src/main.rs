mod auth;
mod connections;
mod registry;
mod relay;

use std::env;
use std::net::SocketAddr;
use std::sync::Arc;

use tonic::transport::Server;
use tracing::info;
use tracing_subscriber::EnvFilter;
use uuid::Uuid;

use detour_core::{AuthMode, BrokerConfig};
use detour_proto::detour::detour_server::DetourServer;

use auth::AuthService;
use connections::{ConnectionMap, PendingRequests};
use relay::RelayService;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env().add_directive("detour=info".parse()?))
        .json()
        .init();

    let config = config_from_env();
    let broker_id = Uuid::new_v4().to_string();

    info!(
        broker_id  = %broker_id,
        port       = config.port,
        auth_mode  = %config.auth_mode,
        redis_url  = %config.redis_url,
        "detour broker starting"
    );

    let registry: Arc<dyn registry::SessionRegistry> = {
        match registry::RedisRegistry::new(&config.redis_url, config.session_ttl_secs) {
            Ok(r) => {
                info!("using Redis session registry");
                Arc::new(r)
            }
            Err(e) => {
                tracing::warn!(error = %e, "Redis unavailable, falling back to in-memory registry");
                Arc::new(registry::MemoryRegistry::new(config.session_ttl_secs))
            }
        }
    };

    let jwt_secret = env::var("DETOUR_JWT_SECRET").ok();
    let auth = Arc::new(AuthService::new(
        config.auth_mode.clone(),
        jwt_secret,
        env::var("DETOUR_GCP_OIDC_AUDIENCE").ok(),
        env::var("DETOUR_ALLOWED_EMAIL_DOMAIN").ok(),
    ));
    let connections = ConnectionMap::default();

    let service = RelayService {
        registry: Arc::clone(&registry),
        connections,
        pending_requests: PendingRequests::default(),
        auth,
        broker_id,
        ttl_secs: config.session_ttl_secs,
    };

    let addr: SocketAddr = format!("{}:{}", config.host, config.port).parse()?;
    info!(%addr, "gRPC server listening");

    Server::builder()
        .add_service(DetourServer::new(service))
        .serve(addr)
        .await?;

    Ok(())
}

fn config_from_env() -> BrokerConfig {
    BrokerConfig {
        host: env::var("DETOUR_HOST").unwrap_or_else(|_| "0.0.0.0".into()),
        port: env::var("DETOUR_PORT")
            .or_else(|_| env::var("PORT"))
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(50051),
        auth_mode: env::var("DETOUR_AUTH_MODE")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(AuthMode::SessionId),
        redis_url: env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379".into()),
        session_ttl_secs: env::var("DETOUR_SESSION_TTL_SECS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(8 * 3600),
        tls_cert_path: env::var("TLS_CERT_PATH").ok(),
        tls_key_path: env::var("TLS_KEY_PATH").ok(),
    }
}
