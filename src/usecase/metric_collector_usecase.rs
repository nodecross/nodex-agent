use crate::repository::metric_repository::{
    Metric, MetricCollectRepository, MetricCollectRepositoryImpl,
};
use tokio::sync::mpsc;

pub struct MetricCollectorUsecase {
    repository: Box<dyn MetricCollectRepository + Send + 'static>,
    sender: mpsc::Sender<Metric>,
    interval: u64,
}

impl MetricCollectorUsecase {
    pub fn new(
        repository: Box<dyn MetricCollectRepository + Send + 'static>,
        sender: mpsc::Sender<Metric>,
        interval: u64,
    ) -> Self {
        MetricCollectorUsecase {
            repository,
            sender,
            interval,
        }
    }

    pub async fn start_collect(&mut self) {
        loop {
            let metrics = self.repository.collect();
            for metric in metrics {
                let _ = self.sender.send(metric).await;
            }

            tokio::time::sleep(tokio::time::Duration::from_secs(self.interval)).await;
        }
    }
}
