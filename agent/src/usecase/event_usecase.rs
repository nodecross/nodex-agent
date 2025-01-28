use crate::{
    repository::event_repository::{EventStoreRepository, EventStoreRequest},
    services::studio::Studio,
};

pub struct EventUsecase<R>
where
    R: EventStoreRepository,
{
    repository: R,
}

impl EventUsecase<Studio> {
    pub fn new() -> Self {
        EventUsecase {
            repository: Studio::new(),
        }
    }
}

impl<R: EventStoreRepository> EventUsecase<R> {
    pub async fn save(&self, request: Vec<EventStoreRequest>) -> anyhow::Result<()> {
        match self.repository.save(request).await {
            Ok(_) => {
                log::info!("save event");
                Ok(())
            }
            Err(e) => {
                log::error!("{:?}", e);
                Err(e)
            }
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

    impl EventStoreRepository for MockEventStoreRepository {
        async fn save(&self, _: Vec<EventStoreRequest>) -> anyhow::Result<()> {
            Ok(())
        }
    }

    #[tokio::test]
    async fn test_save() {
        let usecase = EventUsecase {
            repository: MockEventStoreRepository {},
        };
        let _ = usecase
            .save(vec![EventStoreRequest {
                key: "test".to_string(),
                detail: "test".to_string(),
                occurred_at: chrono::Utc::now(),
            }])
            .await
            .map_err(|e| panic!("{:?}", e));
    }
}
