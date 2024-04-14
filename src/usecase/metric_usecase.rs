use crate::repository::metric_repository::{
    MetricStoreRepository, MetricStoreRequest, MetricWatchRepository,
};
use crate::services::hub::Hub;
use crate::services::metrics::MetricsWatchService;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

pub struct MetricUsecase {
    store_repository: Box<dyn MetricStoreRepository + Send + Sync + 'static>,
    watch_repository: Box<dyn MetricWatchRepository + Send + Sync + 'static>,
    should_stop: Arc<AtomicBool>,
}

impl MetricUsecase {
    pub fn new(should_stop: Arc<AtomicBool>) -> Self {
        MetricUsecase {
            store_repository: Box::new(Hub::new()),
            watch_repository: Box::new(MetricsWatchService::new()),
            should_stop,
        }
    }

    async fn send_request(&self, metric_name: &str, metric_value: f32) -> () {
        let request = MetricStoreRequest {
            device_did: super::get_my_did(),
            timestamp: chrono::Utc::now().naive_utc(),
            metric_name: metric_name.to_string(),
            metric_value,
        };

        match self.store_repository.save(request).await {
            Ok(_) => log::info!("save {}", metric_name),
            Err(e) => log::error!("{:?}", e),
        }
    }

    pub async fn start_collect_metric(&mut self) {
        while !self.should_stop.load(Ordering::Relaxed) {
            let cpu_usage = self.watch_repository.watch_cpu_usage();
            self.send_request("cpu_usage", cpu_usage).await;

            let memory_usage = self.watch_repository.watch_memory_usage();
            self.send_request("memory_usage", memory_usage).await;

            let network_info = self.watch_repository.watch_network_info();
            self.send_request("network_received_bytes", network_info.received_bytes)
                .await;
            self.send_request("network_transmitted_bytes", network_info.transmitted_bytes)
                .await;
            self.send_request("network_received_packets", network_info.recceived_packets)
                .await;
            self.send_request(
                "network_transmitted_packets",
                network_info.transmitted_packets,
            )
            .await;

            let disk_info = self.watch_repository.watch_disk_info();
            self.send_request("disk_written_bytes", disk_info.written_bytes)
                .await;
            self.send_request("disk_read_bytes", disk_info.read_bytes)
                .await;

            tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::repository::metric_repository::{
        DiskMetrics, MetricStoreRepository, MetricWatchRepository, NetworkMetrics,
    };

    pub struct MockMetricStoreRepository {}

    #[async_trait::async_trait]
    impl MetricStoreRepository for MockMetricStoreRepository {
        async fn save(&self, _: MetricStoreRequest) -> anyhow::Result<()> {
            Ok(())
        }
    }

    pub struct MockMetricWatchRepository {}

    impl MetricWatchRepository for MockMetricWatchRepository {
        fn watch_cpu_usage(&mut self) -> f32 {
            0.0
        }

        fn watch_memory_usage(&mut self) -> f32 {
            0.0
        }

        fn watch_network_info(&mut self) -> NetworkMetrics {
            NetworkMetrics {
                received_bytes: 0.0,
                transmitted_bytes: 0.0,
                recceived_packets: 0.0,
                transmitted_packets: 0.0,
            }
        }

        fn watch_disk_info(&mut self) -> DiskMetrics {
            DiskMetrics {
                read_bytes: 0.0,
                written_bytes: 0.0,
            }
        }
    }

    #[tokio::test]
    async fn test_start_collect_metric() {
        let mut usecase = MetricUsecase {
            store_repository: Box::new(MockMetricStoreRepository {}),
            watch_repository: Box::new(MockMetricWatchRepository {}),
            should_stop: Arc::new(AtomicBool::new(false)),
        };

        usecase.should_stop.store(true, Ordering::Relaxed);
        usecase.start_collect_metric().await;
    }
}
