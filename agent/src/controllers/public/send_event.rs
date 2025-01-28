use super::utils::milliseconds_to_time;
use crate::{
    controllers::errors::AgentErrorCode, repository::event_repository::EventStoreRequest,
    usecase::event_usecase::EventUsecase,
};
use axum::extract::Json;
use axum::http::StatusCode;
use serde::{Deserialize, Serialize};

#[derive(Deserialize, Serialize)]
pub struct MessageContainer {
    #[serde(default)]
    key: String,
    #[serde(default)]
    detail: String,
    #[serde(default)]
    occurred_at: u64,
}

pub async fn handler(
    Json(json): Json<Vec<MessageContainer>>,
) -> Result<StatusCode, AgentErrorCode> {
    let events = json
        .iter()
        .map(|m| {
            if m.key.is_empty() {
                return Err(AgentErrorCode::SendEventNoKey);
            }
            if m.detail.is_empty() {
                return Err(AgentErrorCode::SendEventNoDetail);
            }

            let occurred_at = milliseconds_to_time(m.occurred_at)
                .ok_or(AgentErrorCode::SendEventInvalidOccurredAt)?;

            Ok(EventStoreRequest {
                key: m.key.clone(),
                detail: m.detail.clone(),
                occurred_at,
            })
        })
        .collect::<Result<Vec<EventStoreRequest>, AgentErrorCode>>()?;

    let usecase = EventUsecase::new();
    match usecase.save(events).await {
        Ok(_) => {
            log::info!("save event");
            Ok(StatusCode::NO_CONTENT)
        }
        Err(e) => {
            log::error!("{:?}", e);
            Err(AgentErrorCode::SendEventInternal)?
        }
    }
}
