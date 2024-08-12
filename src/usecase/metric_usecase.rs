use crate::config::SingletonAppConfig;
use crate::repository::metric_repository::{
    MetricStoreRepository, MetricsCacheRepository, MetricsWatchRepository,
};
use crate::services::metrics::MetricsInMemoryCacheService;
use std::{sync::Arc, time::Duration};
use tokio::sync::Mutex as TokioMutex;
use tokio::sync::Notify;

pub struct MetricUsecase {
    store_repository: Box<dyn MetricStoreRepository>,
    watch_repository: Box<dyn MetricsWatchRepository>,
    config: Box<SingletonAppConfig>,
    cache_repository: Arc<TokioMutex<MetricsInMemoryCacheService>>,
    shutdown_notify: Arc<Notify>,
}

impl MetricUsecase {
    pub fn new(
        store_repository: Box<dyn MetricStoreRepository>,
        watch_repository: Box<dyn MetricsWatchRepository>,
        config: Box<SingletonAppConfig>,
        cache_repository: Arc<TokioMutex<MetricsInMemoryCacheService>>,
        shutdown_notify: Arc<Notify>,
    ) -> Self {
        MetricUsecase {
            store_repository,
            watch_repository,
            config,
            cache_repository,
            shutdown_notify,
        }
    }

    pub async fn collect_task(&mut self) {
        let interval_time: u64 = self.config.lock().get_metric_collect_interval();
        let mut interval = tokio::time::interval(Duration::from_secs(interval_time));
        loop {
            tokio::select! {
                _ = interval.tick() => {
                    let metrics = self.watch_repository.watch_metrics();
                    for metric in metrics {
                        self.cache_repository.lock().await.push(chrono::Utc::now(), vec![metric]);
                    }
                    log::info!("collected metrics");
                }
                _ = self.shutdown_notify.notified() => {
                    break;
                },
            }
        }
    }

    pub async fn send_task(&mut self) {
        let interval_time: u64 = self.config.lock().get_metric_send_interval();
        let mut interval = tokio::time::interval(Duration::from_secs(interval_time));
        loop {
            tokio::select! {
                _ = interval.tick() => {
                    let metrics_with_timestamp_list = self.cache_repository.lock().await.get();

                    if metrics_with_timestamp_list.is_empty() {
                        continue;
                    }

                    match self.store_repository.save(metrics_with_timestamp_list).await {
                        Ok(_) => {
                            self.cache_repository.lock().await.clear();
                            log::info!("sent metrics");
                        },
                        Err(e) => log::error!("failed to send metric{:?}", e),
                    }
                }
                _ = self.shutdown_notify.notified() => {
                    break;
                },
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        app_config,
        repository::metric_repository::{
            Metric, MetricStoreRepository, MetricType, MetricsWatchRepository, MetricsWithTimestamp,
        },
    };
    pub struct MockMetricStoreRepository {}

    #[async_trait::async_trait]
    impl MetricStoreRepository for MockMetricStoreRepository {
        async fn save(&self, _: Vec<MetricsWithTimestamp>) -> anyhow::Result<()> {
            Ok(())
        }
    }

    pub struct MockMetricWatchRepository {}

    impl MetricsWatchRepository for MockMetricWatchRepository {
        fn watch_metrics(&mut self) -> Vec<Metric> {
            vec![
                Metric {
                    metric_type: MetricType::CpuUsage,
                    value: 0.0,
                },
                Metric {
                    metric_type: MetricType::MemoryUsage,
                    value: 0.0,
                },
            ]
        }
    }

    #[tokio::test]
    async fn test_collect_task() {
        let notify = Arc::new(Notify::new());
        let notify_clone = notify.clone();
        let mut usecase = MetricUsecase {
            store_repository: Box::new(MockMetricStoreRepository {}),
            watch_repository: Box::new(MockMetricWatchRepository {}),
            config: app_config(),
            cache_repository: Arc::new(TokioMutex::new(MetricsInMemoryCacheService::new())),
            shutdown_notify: notify_clone,
        };
        notify.notify_one();
        usecase.collect_task().await;
    }

    #[tokio::test]
    async fn test_send_task() {
        let notify = Arc::new(Notify::new());
        let notify_clone = notify.clone();
        let mut usecase = MetricUsecase {
            store_repository: Box::new(MockMetricStoreRepository {}),
            watch_repository: Box::new(MockMetricWatchRepository {}),
            config: app_config(),
            cache_repository: Arc::new(TokioMutex::new(MetricsInMemoryCacheService::new())),
            shutdown_notify: notify_clone,
        };
        notify.notify_one();
        usecase.send_task().await;
    }
}
