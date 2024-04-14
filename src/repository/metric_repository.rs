use chrono::NaiveDateTime;
use serde::Serialize;

#[derive(Debug, Serialize, Clone)]
pub struct NetworkMetrics {
    pub received_bytes: f32,
    pub transmitted_bytes: f32,
    pub recceived_packets: f32,
    pub transmitted_packets: f32,
}

#[derive(Debug, Serialize, Clone)]
pub struct DiskMetrics {
    pub written_bytes: f32,
    pub read_bytes: f32,
}

pub trait MetricWatchRepository {
    fn cpu_usage(&mut self) -> f32;
    fn memory_usage(&mut self) -> f32;
    fn network_info(&mut self) -> NetworkMetrics;
    fn disk_info(&mut self) -> DiskMetrics;
}

#[derive(Debug, Serialize, Clone)]
pub struct MetricStoreRequest {
    pub device_did: String,
    pub timestamp: NaiveDateTime,
    pub metric_name: String,
    pub metric_value: f32,
}

#[async_trait::async_trait]
pub trait MetricStoreRepository {
    async fn save(&self, request: MetricStoreRequest) -> anyhow::Result<()>;
}
