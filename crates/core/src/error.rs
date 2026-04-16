use thiserror::Error;

#[derive(Debug, Error)]
pub enum DetourError {
    #[error("invalid session ID: {0}")]
    InvalidSessionId(String),

    #[error("invalid auth mode: {0}")]
    InvalidAuthMode(String),

    #[error("session not found: {0}")]
    SessionNotFound(String),

    #[error("session expired: {0}")]
    SessionExpired(String),

    #[error("broker connection failed: {0}")]
    BrokerConnectionFailed(String),

    #[error("tunnel error: {0}")]
    TunnelError(String),

    #[error("relay error: {0}")]
    RelayError(String),

    #[error("registry error: {0}")]
    RegistryError(String),

    #[error("auth error: {0}")]
    AuthError(String),

    #[error("config error: {0}")]
    ConfigError(String),

    #[error(transparent)]
    Other(#[from] anyhow::Error),
}
