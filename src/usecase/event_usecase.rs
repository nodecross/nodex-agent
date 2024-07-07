use crate::{
    repository::event_repository::{EventStoreRepository, EventStoreRequest},
    services::studio::Studio,
};

pub struct EventUsecase {
    repository: Box<dyn EventStoreRepository>,
}

impl EventUsecase {
    pub fn new() -> Self {
        EventUsecase {
            repository: Box::new(Studio::new()),
        }
    }

    pub async fn save(&self, request: EventStoreRequest) {
        match self.repository.save(request).await {
            Ok(_) => log::info!("save event"),
            Err(e) => log::error!("{:?}", e),
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        repository::event_repository::{EventStoreRepository, EventStoreRequest},
        usecase::event_usecase::EventUsecase,
    };

    pub struct MockEventStoreRepository {}

    #[async_trait::async_trait]
    impl EventStoreRepository for MockEventStoreRepository {
        async fn save(&self, _: EventStoreRequest) -> anyhow::Result<()> {
            Ok(())
        }
    }

    #[tokio::test]
    async fn test_save() {
        let usecase = EventUsecase {
            repository: Box::new(MockEventStoreRepository {}),
        };
        usecase
            .save(EventStoreRequest {
                key: "test".to_string(),
                detail: "test".to_string(),
                occurred_at: chrono::Utc::now(),
            })
            .await;
    }
}
