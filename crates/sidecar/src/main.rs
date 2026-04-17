mod cache;
mod config;
mod inspector;
mod proxy;

use std::net::SocketAddr;
use std::sync::Arc;

use axum::{routing::any, Router};
use tonic::transport::{Channel, ClientTlsConfig};
use tracing::info;
use tracing_subscriber::EnvFilter;

use detour_proto::detour::detour_client::DetourClient;

use cache::SessionCache;
use inspector::CachedResolver;
use proxy::{handler, ProxyState};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env().add_directive("detour=info".parse()?))
        .json()
        .init();

    let cfg = config::from_env();

    info!(
        listen_port  = cfg.listen_port,
        app_upstream = %cfg.app_upstream,
        broker_url   = %cfg.broker_url,
        "detour sidecar starting"
    );

    let mut endpoint = Channel::from_shared(cfg.broker_url.clone())?;
    if cfg.broker_url.starts_with("https://") {
        endpoint = endpoint.tls_config(ClientTlsConfig::new().with_webpki_roots())?;
    }
    let channel = endpoint.connect_lazy();

    let broker_client = DetourClient::new(channel.clone());
    let lookup_client = DetourClient::new(channel);
    let cache = SessionCache::new(cfg.cache_ttl_secs);
    let resolver = Arc::new(CachedResolver::new(
        cache,
        lookup_client,
        cfg.service_name.clone(),
    ));

    let state = ProxyState {
        resolver,
        app_upstream: cfg.app_upstream.clone(),
        broker_client,
        service_name: cfg.service_name.clone(),
        log_routed: cfg.log_routed_requests,
        max_body_mb: cfg.max_body_size_mb,
    };

    let app = Router::new().fallback(any(handler)).with_state(state);

    let addr: SocketAddr = format!("0.0.0.0:{}", cfg.listen_port).parse()?;
    info!(%addr, "HTTP listener ready");

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}
