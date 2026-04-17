use serde::{Deserialize, Serialize};
use std::fmt;
use uuid::Uuid;

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SessionId(String);

impl SessionId {
    pub fn new() -> Self {
        Self(Uuid::new_v4().to_string())
    }

    pub fn from_string(s: String) -> Result<Self, crate::DetourError> {
        Uuid::parse_str(&s).map_err(|_| crate::DetourError::InvalidSessionId(s.clone()))?;
        Ok(Self(s))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Default for SessionId {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for SessionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl TryFrom<String> for SessionId {
    type Error = crate::DetourError;
    fn try_from(s: String) -> Result<Self, Self::Error> {
        Self::from_string(s)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum AuthMode {
    SessionId,
    SignedToken,
}

impl fmt::Display for AuthMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AuthMode::SessionId   => f.write_str("session-id"),
            AuthMode::SignedToken => f.write_str("signed-token"),
        }
    }
}

impl std::str::FromStr for AuthMode {
    type Err = crate::DetourError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "session-id"   => Ok(AuthMode::SessionId),
            "signed-token" => Ok(AuthMode::SignedToken),
            other          => Err(crate::DetourError::InvalidAuthMode(other.to_string())),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionRecord {
    pub session_id:      SessionId,
    pub connection_id:   String,
    pub broker_instance: String,
    pub auth_mode:       AuthMode,
    pub registered_at:   u64,
    pub last_heartbeat:  u64,
    pub routes:          Vec<crate::ServiceRoute>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TunnelStatus {
    Connecting,
    Connected,
    Reconnecting,
    Stopped,
    Error(String),
}

impl fmt::Display for TunnelStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TunnelStatus::Connecting   => f.write_str("connecting"),
            TunnelStatus::Connected    => f.write_str("connected"),
            TunnelStatus::Reconnecting => f.write_str("reconnecting"),
            TunnelStatus::Stopped      => f.write_str("stopped"),
            TunnelStatus::Error(msg)   => write!(f, "error: {}", msg),
        }
    }
}
