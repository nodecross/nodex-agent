use actix_web::{web, HttpRequest, HttpResponse};
use chrono::DateTime;
use serde::{Deserialize, Serialize};

use crate::{
    errors::{create_agent_error, AgentErrorCode},
    repository::event_repository::EventStoreRequest,
    usecase::event_usecase::EventUsecase,
};

#[derive(Deserialize, Serialize)]
pub struct MessageContainer {
    key: String,
    detail: String,
    occurred_at: String,
}

pub async fn handler(
    _req: HttpRequest,
    web::Json(json): web::Json<MessageContainer>,
) -> actix_web::Result<HttpResponse> {
    if json.key.is_empty() {
        return Ok(create_agent_error(AgentErrorCode::SendEventNoKey));
    }
    if json.detail.is_empty() {
        return Ok(create_agent_error(AgentErrorCode::SendEventNoDetail));
    }

    let occurred_at = match json.occurred_at.parse::<i64>() {
        Ok(timestamp) => match DateTime::from_timestamp(timestamp, 0) {
            Some(dt) => dt,
            _ => {
                return Ok(create_agent_error(
                    AgentErrorCode::SendEventInvalidOccurredAt,
                ))
            }
        },
        Err(_) => {
            return Ok(create_agent_error(
                AgentErrorCode::SendEventInvalidOccurredAt,
            ))
        }
    };

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
            Ok(create_agent_error(AgentErrorCode::SendEventInternal))
        }
    }
}
