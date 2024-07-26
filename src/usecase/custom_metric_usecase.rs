use crate::{
    repository::custom_metric_repository::{CustomMetricStoreRepository, CustomMetricStoreRequest},
    services::studio::Studio,
};

pub struct CustomMetricUsecase {
    repository: Box<dyn CustomMetricStoreRepository>,
}

impl CustomMetricUsecase {
    pub fn new() -> Self {
        CustomMetricUsecase {
            repository: Box::new(Studio::new()),
        }
    }

    pub async fn save(&self, request: CustomMetricStoreRequest) -> anyhow::Result<()> {
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

    #[async_trait::async_trait]
    impl CustomMetricStoreRepository for MockCustomMetricStoreRepository {
        async fn save(&self, _: CustomMetricStoreRequest) -> anyhow::Result<()> {
            Ok(())
        }
    }

    #[tokio::test]
    async fn test_save() {
        let usecase = CustomMetricUsecase {
            repository: Box::new(MockCustomMetricStoreRepository {}),
        };

        let request = CustomMetricStoreRequest {
            key: "test_key".to_string(),
            value: 10.52,
            occurred_at: chrono::Utc::now(),
        };

        if let Err(e) = usecase.save(request).await {
            panic!("{:?}", e);
        }
    }
}
