use std::env;

use detour_core::{AuthMode, SidecarConfig};

pub fn from_env() -> SidecarConfig {
    SidecarConfig {
        broker_url: env::var("DETOUR_BROKER_URL")
            .unwrap_or_else(|_| "http://localhost:50051".into()),
        app_upstream: env::var("APP_UPSTREAM").unwrap_or_else(|_| "localhost:8080".into()),
        auth_mode: env::var("DETOUR_AUTH_MODE")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(AuthMode::SessionId),
        fallback_on_miss: env::var("DETOUR_FALLBACK_ON_MISS")
            .map(|v| v != "false")
            .unwrap_or(true),
        cache_ttl_secs: env::var("DETOUR_CACHE_TTL_SECONDS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(30),
        log_routed_requests: env::var("DETOUR_LOG_ROUTED_REQUESTS")
            .map(|v| v != "false")
            .unwrap_or(true),
        listen_port: env::var("DETOUR_LISTEN_PORT")
            .or_else(|_| env::var("PORT"))
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(8000),
        max_body_size_mb: env::var("DETOUR_MAX_BODY_SIZE_MB")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(10),
        service_name: env::var("DETOUR_SERVICE_NAME").unwrap_or_default(),
    }
}
