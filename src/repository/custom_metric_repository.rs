use chrono::{DateTime, Utc};
use serde::Serialize;

#[derive(Debug, Serialize, Clone)]
pub struct CustomMetricStoreRequest {
    pub key: String,
    pub value: f32,
    pub occurred_at: DateTime<Utc>,
}

#[async_trait::async_trait]
pub trait CustomMetricStoreRepository {
    async fn save(&self, request: CustomMetricStoreRequest) -> anyhow::Result<()>;
}
