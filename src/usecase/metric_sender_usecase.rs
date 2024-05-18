use crate::repository::metric_repository::{
    Metric, MetricFileStoreRepository, MetricInmemoryStoreRepository, MetricSendRepository,
    MetricSendRepositoryImpl, MetricStoreRepository,
};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;
use tokio::sync::Notify;

pub struct MetricSenderUsecase {
    inmemory_store_repository: Box<dyn MetricStoreRepository + Send + 'static>,
    file_store_repository: Box<dyn MetricStoreRepository + Send + 'static>,
    send_repository: Box<dyn MetricSendRepository + Send + Sync + 'static>,
    receiver: mpsc::Receiver<Metric>,
    interval: u64,
}

impl MetricSenderUsecase {
    pub fn new(
        inmemory_store_repository: Box<dyn MetricStoreRepository + Send + 'static>,
        file_store_repository: Box<dyn MetricStoreRepository + Send + 'static>,
        send_repository: Box<dyn MetricSendRepository + Send + Sync + 'static>,
        receiver: mpsc::Receiver<Metric>,
        interval: u64,
    ) -> Self {
        MetricSenderUsecase {
            inmemory_store_repository,
            file_store_repository,
            send_repository,
            receiver,
            interval,
        }
    }

    pub async fn start_send(&mut self, shutdown_notify: Arc<Notify>) {
        loop {
            tokio::select! {
                _ = shutdown_notify.notified() => {
                    let metrics = self.inmemory_store_repository.get_all();
                    self.file_store_repository.set(metrics).unwrap();
                    break;
                },
                _ = tokio::time::sleep(Duration::from_secs(self.interval)) => {
                    let metrics = self.inmemory_store_repository.get_all();
                    let _ = self.send_repository.send(metrics);
                    self.inmemory_store_repository.flush().unwrap();
                },
                metric = self.receiver.recv() => {
                    let mut metrics = vec![];
                    if let Some(metric) = metric {
                        metrics.push(metric);
                    }
                    self.inmemory_store_repository.set(metrics).unwrap();
                }
            }
        }
    }
}
