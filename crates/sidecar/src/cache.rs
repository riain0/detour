use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;

use detour_core::{SessionId, SessionRecord};

struct Entry {
    record:    SessionRecord,
    inserted:  Instant,
    ttl:       Duration,
}

impl Entry {
    fn is_fresh(&self) -> bool {
        self.inserted.elapsed() < self.ttl
    }
}

#[derive(Clone)]
pub struct SessionCache {
    inner: Arc<Mutex<HashMap<String, Entry>>>,
    ttl:   Duration,
}

impl SessionCache {
    pub fn new(ttl_secs: u64) -> Self {
        Self {
            inner: Arc::new(Mutex::new(HashMap::new())),
            ttl:   Duration::from_secs(ttl_secs),
        }
    }

    pub async fn get(&self, id: &SessionId) -> Option<SessionRecord> {
        let mut map = self.inner.lock().await;
        match map.get(&id.to_string()) {
            Some(e) if e.is_fresh() => Some(e.record.clone()),
            Some(_) => {
                map.remove(&id.to_string());
                None
            }
            None => None,
        }
    }

    pub async fn insert(&self, record: SessionRecord) {
        self.inner.lock().await.insert(
            record.session_id.to_string(),
            Entry {
                record,
                inserted: Instant::now(),
                ttl:      self.ttl,
            },
        );
    }
}
