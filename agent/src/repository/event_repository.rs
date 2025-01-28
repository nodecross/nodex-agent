use chrono::{DateTime, Utc};
use serde::Serialize;

#[derive(Debug, Serialize, Clone)]
pub struct EventStoreRequest {
    pub key: String,
    pub detail: String,
    pub occurred_at: DateTime<Utc>,
}

#[trait_variant::make(Send)]
pub trait EventStoreRepository {
    async fn save(&self, request: Vec<EventStoreRequest>) -> anyhow::Result<()>;
}
