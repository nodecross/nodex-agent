use chrono::{DateTime, Utc};
use serde::Serialize;

#[derive(Debug, Serialize, Clone)]
pub struct EventStoreRequest {
    pub key: String,
    pub detail: String,
    pub occurred_at: DateTime<Utc>,
}

#[async_trait::async_trait]
pub trait EventStoreRepository {
    async fn save(&self, request: EventStoreRequest) -> anyhow::Result<()>;
}
