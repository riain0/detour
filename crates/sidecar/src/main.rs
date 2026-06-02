mod cache;
mod config;
mod inspector;
mod proxy;
mod raw;

use std::net::SocketAddr;
use std::sync::Arc;

use tonic::transport::{Channel, ClientTlsConfig};
use tracing::{info, warn};
use tracing_subscriber::EnvFilter;

use detour_proto::detour::detour_client::DetourClient;

use cache::SessionCache;
use inspector::CachedResolver;
use proxy::{handle_conn, ProxyState};

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
    };

    let addr: SocketAddr = format!("0.0.0.0:{}", cfg.listen_port).parse()?;
    let listener = tokio::net::TcpListener::bind(addr).await?;
    info!(%addr, "raw TCP listener ready");

    loop {
        let (sock, _peer) = match listener.accept().await {
            Ok(conn) => conn,
            Err(e) => {
                warn!(error = %e, "accept failed");
                continue;
            }
        };
        let _ = sock.set_nodelay(true);
        let state = state.clone();
        tokio::spawn(async move {
            handle_conn(sock, state).await;
        });
    }
}
