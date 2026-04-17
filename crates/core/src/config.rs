use serde::{Deserialize, Serialize};

use crate::AuthMode;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BrokerConfig {
    pub host:             String,
    pub port:             u16,
    pub auth_mode:        AuthMode,
    pub redis_url:        String,
    pub session_ttl_secs: u64,
    pub tls_cert_path:    Option<String>,
    pub tls_key_path:     Option<String>,
}

impl Default for BrokerConfig {
    fn default() -> Self {
        Self {
            host:             "0.0.0.0".into(),
            port:             50051,
            auth_mode:        AuthMode::SessionId,
            redis_url:        "redis://127.0.0.1:6379".into(),
            session_ttl_secs: 8 * 3600, // 8h
            tls_cert_path:    None,
            tls_key_path:     None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SidecarConfig {
    pub broker_url:          String,
    pub app_upstream:        String,
    pub auth_mode:           AuthMode,
    pub fallback_on_miss:    bool,
    pub cache_ttl_secs:      u64,
    pub log_routed_requests: bool,
    pub listen_port:         u16,
    pub max_body_size_mb:    u64,
    pub service_name:        String,
}

impl Default for SidecarConfig {
    fn default() -> Self {
        Self {
            broker_url:          "http://localhost:50051".into(),
            app_upstream:        "localhost:8080".into(),
            auth_mode:           AuthMode::SessionId,
            fallback_on_miss:    true,
            cache_ttl_secs:      30,
            log_routed_requests: true,
            listen_port:         8000,
            max_body_size_mb:    10,
            service_name:        String::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceRoute {
    pub service_name: String,
    pub local_port:   u16,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentConfig {
    pub broker_url:  String,
    pub routes:      Vec<ServiceRoute>,
    pub auth_mode:   AuthMode,
    pub socks5_port: u16,
}
