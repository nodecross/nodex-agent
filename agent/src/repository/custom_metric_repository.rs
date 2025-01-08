use chrono::{DateTime, Utc};
use protocol::cbor::types::CustomMetric;
use serde::Serialize;

#[derive(Debug, Serialize, Clone)]
pub struct CustomMetricStoreRequest {
    pub key: String,
    pub value: f32,
    pub occurred_at: DateTime<Utc>,
}

#[trait_variant::make(Send)]
pub trait CustomMetricStoreRepository {
    async fn save(&self, request: Vec<CustomMetric>) -> anyhow::Result<()>;
}
