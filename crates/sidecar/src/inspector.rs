use async_trait::async_trait;
use http::HeaderMap;
use tonic::transport::Channel;
use tracing::warn;
use uuid::Uuid;

use detour_core::{SessionId, SessionRecord};
use detour_proto::detour::{detour_client::DetourClient, LookupRequest};

use crate::cache::SessionCache;

pub const ROUTE_HEADER: &str = "x-route-to";

#[async_trait]
pub trait SessionResolver: Send + Sync {
    async fn resolve(&self, headers: &HeaderMap) -> Option<SessionRecord>;
}

pub struct CachedResolver {
    cache:            SessionCache,
    client:           DetourClient<Channel>,
    expected_service: String,
}

impl CachedResolver {
    pub fn new(cache: SessionCache, client: DetourClient<Channel>, expected_service: String) -> Self {
        Self { cache, client, expected_service }
    }
}

#[async_trait]
impl SessionResolver for CachedResolver {
    async fn resolve(&self, headers: &HeaderMap) -> Option<SessionRecord> {
        let raw = headers.get(ROUTE_HEADER)?.to_str().ok()?;

        // Validate UUID v4 format; drop invalid values (pass through to app)
        if Uuid::parse_str(raw).is_err() {
            warn!(value = raw, "invalid X-Route-To value, passing through");
            return None;
        }

        let sid = SessionId::from_string(raw.to_lowercase()).ok()?;

        // Fast path: in-memory cache hit
        if let Some(record) = self.cache.get(&sid).await {
            if !self.expected_service.is_empty()
                && record.service_name != self.expected_service
            {
                return None;
            }
            return Some(record);
        }

        // Slow path: broker LookupSession RPC
        let mut client = self.client.clone();
        match client
            .lookup_session(LookupRequest {
                session_id: sid.to_string(),
            })
            .await
        {
            Ok(resp) => {
                let r = resp.into_inner();
                if !r.found {
                    return None;
                }
                let record = detour_core::SessionRecord {
                    session_id:      sid.clone(),
                    connection_id:   String::new(),
                    broker_instance: String::new(),
                    service_name:    r.service_name,
                    auth_mode:       r.auth_mode.parse().unwrap_or(detour_core::AuthMode::SessionId),
                    registered_at:   0,
                    last_heartbeat:  0,
                    allowed_services: vec![],
                };
                if !self.expected_service.is_empty()
                    && record.service_name != self.expected_service
                {
                    warn!(
                        session_service = %record.service_name,
                        expected        = %self.expected_service,
                        "session service mismatch, passing through"
                    );
                    return None;
                }
                self.cache.insert(record.clone()).await;
                Some(record)
            }
            Err(e) => {
                warn!(error = %e, "broker LookupSession failed");
                None
            }
        }
    }
}
