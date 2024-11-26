use actix_web::{web, HttpRequest, HttpResponse};

use serde::{Deserialize, Serialize};

use crate::{
    errors::{AgentError, AgentErrorCode},
    repository::event_repository::EventStoreRequest,
    usecase::event_usecase::EventUsecase,
};

use super::utils::milliseconds_to_time;

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
    _req: HttpRequest,
    web::Json(json): web::Json<MessageContainer>,
) -> actix_web::Result<HttpResponse, AgentError> {
    if json.key.is_empty() {
        Err(AgentErrorCode::SendEventNoKey)?
    }
    if json.detail.is_empty() {
        Err(AgentErrorCode::SendEventNoDetail)?
    }

    let occurred_at =
        milliseconds_to_time(json.occurred_at).ok_or(AgentErrorCode::SendEventInvalidOccurredAt)?;

    let usecase = EventUsecase::new();
    match usecase
        .save(EventStoreRequest {
            key: json.key,
            detail: json.detail,
            occurred_at,
        })
        .await
    {
        Ok(_) => {
            log::info!("save event");
            Ok(HttpResponse::NoContent().finish())
        }
        Err(e) => {
            log::error!("{:?}", e);
            Err(AgentErrorCode::SendEventInternal)?
        }
    }
}
