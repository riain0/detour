use async_trait::async_trait;
use redis::AsyncCommands;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::Mutex;

use detour_core::{AuthMode, DetourError, SessionId, SessionRecord};

#[async_trait]
pub trait SessionRegistry: Send + Sync {
    async fn register(&self, record: SessionRecord) -> Result<(), DetourError>;
    async fn lookup(&self, id: &SessionId) -> Result<Option<SessionRecord>, DetourError>;
    async fn heartbeat(&self, id: &SessionId) -> Result<(), DetourError>;
    async fn expire(&self, id: &SessionId) -> Result<(), DetourError>;
}

// ── In-memory registry (tests / no-Redis mode) ───────────────────────────────

pub struct MemoryRegistry {
    sessions: Arc<Mutex<HashMap<String, SessionRecord>>>,
    ttl_secs: u64,
}

impl MemoryRegistry {
    pub fn new(ttl_secs: u64) -> Self {
        Self {
            sessions: Arc::new(Mutex::new(HashMap::new())),
            ttl_secs,
        }
    }

    fn now() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    }
}

#[async_trait]
impl SessionRegistry for MemoryRegistry {
    async fn register(&self, record: SessionRecord) -> Result<(), DetourError> {
        let mut sessions = self.sessions.lock().await;
        sessions.insert(record.session_id.to_string(), record);
        Ok(())
    }

    async fn lookup(&self, id: &SessionId) -> Result<Option<SessionRecord>, DetourError> {
        let mut sessions = self.sessions.lock().await;
        let key = id.to_string();
        if let Some(record) = sessions.get(&key) {
            let age = Self::now().saturating_sub(record.last_heartbeat);
            if age > self.ttl_secs {
                sessions.remove(&key);
                return Ok(None);
            }
            Ok(Some(record.clone()))
        } else {
            Ok(None)
        }
    }

    async fn heartbeat(&self, id: &SessionId) -> Result<(), DetourError> {
        let mut sessions = self.sessions.lock().await;
        if let Some(record) = sessions.get_mut(&id.to_string()) {
            record.last_heartbeat = Self::now();
            Ok(())
        } else {
            Err(DetourError::SessionNotFound(id.to_string()))
        }
    }

    async fn expire(&self, id: &SessionId) -> Result<(), DetourError> {
        let mut sessions = self.sessions.lock().await;
        sessions.remove(&id.to_string());
        Ok(())
    }
}

// ── Redis registry ────────────────────────────────────────────────────────────

pub struct RedisRegistry {
    client:   redis::Client,
    ttl_secs: u64,
}

impl RedisRegistry {
    pub fn new(redis_url: &str, ttl_secs: u64) -> Result<Self, DetourError> {
        let client = redis::Client::open(redis_url)
            .map_err(|e| DetourError::RegistryError(e.to_string()))?;

        // Verify Redis is reachable before committing to this registry.
        // Uses the synchronous client for the probe so new() stays non-async.
        let mut conn = client
            .get_connection()
            .map_err(|e| DetourError::RegistryError(e.to_string()))?;
        redis::cmd("PING")
            .query::<String>(&mut conn)
            .map_err(|e| DetourError::RegistryError(e.to_string()))?;

        Ok(Self { client, ttl_secs })
    }

    fn key(id: &SessionId) -> String {
        format!("localroute:session:{}", id)
    }

    fn now() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    }
}

#[async_trait]
impl SessionRegistry for RedisRegistry {
    async fn register(&self, record: SessionRecord) -> Result<(), DetourError> {
        let mut conn = self
            .client
            .get_multiplexed_async_connection()
            .await
            .map_err(|e| DetourError::RegistryError(e.to_string()))?;

        let key              = Self::key(&record.session_id);
        let allowed_services = record.allowed_services.join(",");
        let now              = Self::now();

        let _: () = redis::pipe()
            .hset_multiple(
                &key,
                &[
                    ("connection_id",    record.connection_id.as_str()),
                    ("broker_instance",  record.broker_instance.as_str()),
                    ("service_name",     record.service_name.as_str()),
                    ("auth_mode",        record.auth_mode.to_string().as_str()),
                    ("registered_at",    &now.to_string()),
                    ("last_heartbeat",   &now.to_string()),
                    ("allowed_services", allowed_services.as_str()),
                ],
            )
            .expire(&key, self.ttl_secs as i64)
            .query_async(&mut conn)
            .await
            .map_err(|e| DetourError::RegistryError(e.to_string()))?;

        Ok(())
    }

    async fn lookup(&self, id: &SessionId) -> Result<Option<SessionRecord>, DetourError> {
        let mut conn = self
            .client
            .get_multiplexed_async_connection()
            .await
            .map_err(|e| DetourError::RegistryError(e.to_string()))?;

        let key: String = Self::key(id);
        let fields: HashMap<String, String> = conn
            .hgetall(&key)
            .await
            .map_err(|e| DetourError::RegistryError(e.to_string()))?;

        if fields.is_empty() {
            return Ok(None);
        }

        let auth_mode = fields
            .get("auth_mode")
            .and_then(|s| s.parse::<AuthMode>().ok())
            .unwrap_or(AuthMode::SessionId);

        let allowed_services = fields
            .get("allowed_services")
            .map(|s| s.split(',').map(|p| p.to_string()).collect())
            .unwrap_or_default();

        Ok(Some(SessionRecord {
            session_id:      id.clone(),
            connection_id:   fields.get("connection_id").cloned().unwrap_or_default(),
            broker_instance: fields.get("broker_instance").cloned().unwrap_or_default(),
            service_name:    fields.get("service_name").cloned().unwrap_or_default(),
            auth_mode,
            registered_at:   fields.get("registered_at").and_then(|v| v.parse().ok()).unwrap_or(0),
            last_heartbeat:  fields.get("last_heartbeat").and_then(|v| v.parse().ok()).unwrap_or(0),
            allowed_services,
        }))
    }

    async fn heartbeat(&self, id: &SessionId) -> Result<(), DetourError> {
        let mut conn = self
            .client
            .get_multiplexed_async_connection()
            .await
            .map_err(|e| DetourError::RegistryError(e.to_string()))?;

        let key = Self::key(id);
        let now = Self::now().to_string();
        let _: () = redis::pipe()
            .hset(&key, "last_heartbeat", &now)
            .expire(&key, self.ttl_secs as i64)
            .query_async(&mut conn)
            .await
            .map_err(|e| DetourError::RegistryError(e.to_string()))?;

        Ok(())
    }

    async fn expire(&self, id: &SessionId) -> Result<(), DetourError> {
        let mut conn = self
            .client
            .get_multiplexed_async_connection()
            .await
            .map_err(|e| DetourError::RegistryError(e.to_string()))?;

        let key: String = Self::key(id);
        let _: () = conn
            .del(&key)
            .await
            .map_err(|e| DetourError::RegistryError(e.to_string()))?;

        Ok(())
    }
}
