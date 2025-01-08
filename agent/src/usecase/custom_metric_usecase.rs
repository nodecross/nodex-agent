use crate::{
    repository::custom_metric_repository::CustomMetricStoreRepository,
    services::studio::Studio,
};
use protocol::cbor::types::CustomMetric;

pub struct CustomMetricUsecase<R>
where
    R: CustomMetricStoreRepository,
{
    repository: R,
}

impl CustomMetricUsecase<Studio> {
    pub fn new() -> Self {
        CustomMetricUsecase {
            repository: Studio::new(),
        }
    }
}

impl<R: CustomMetricStoreRepository> CustomMetricUsecase<R> {
    pub async fn save(&self, request: Vec<CustomMetric>) -> anyhow::Result<()> {
        if let Err(e) = self.repository.save(request).await {
            log::error!("{:?}", e);
            Err(e)
        } else {
            log::info!("save custom metrics");
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        repository::custom_metric_repository::{
            CustomMetricStoreRepository, CustomMetricStoreRequest,
        },
        usecase::custom_metric_usecase::CustomMetricUsecase,
    };
    pub struct MockCustomMetricStoreRepository {}
    use protocol::cbor::types::CustomMetric;

    impl CustomMetricStoreRepository for MockCustomMetricStoreRepository {
        async fn save(&self, _: Vec<CustomMetric>) -> anyhow::Result<()> {
            Ok(())
        }
    }

    #[tokio::test]
    async fn test_save() {
        let usecase = CustomMetricUsecase {
            repository: MockCustomMetricStoreRepository {},
        };

        let request = vec![CustomMetricStoreRequest {
            key: "test_key".to_string(),
            value: 10.52,
            occurred_at: chrono::Utc::now(),
        }];

        if let Err(e) = usecase.save(request).await {
            panic!("{:?}", e);
        }
    }
}
