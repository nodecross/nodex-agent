use actix_web::{web, HttpRequest, HttpResponse};
use chrono::DateTime;
use serde::{Deserialize, Serialize};

use crate::{
    errors::{create_agent_error, AgentErrorCode},
    repository::custom_metric_repository::CustomMetricStoreRequest,
    usecase::custom_metric_usecase::CustomMetricUsecase,
};

#[derive(Deserialize, Serialize)]
pub struct MessageContainer {
    key: String,
    value: f32,
    occurred_at: String,
}

pub async fn handler(
    _req: HttpRequest,
    web::Json(json): web::Json<MessageContainer>,
) -> actix_web::Result<HttpResponse> {
    if json.key.is_empty() {
        return Ok(create_agent_error(AgentErrorCode::SendCustomMetricNoKey));
    }

    let occurred_at = match json.occurred_at.parse::<i64>() {
        Ok(timestamp) => match DateTime::from_timestamp(timestamp, 0) {
            Some(dt) => dt,
            _ => {
                return Ok(create_agent_error(
                    AgentErrorCode::SendCustomMetricInvalidOccurredAt,
                ));
            }
        },
        Err(_) => {
            return Ok(create_agent_error(
                AgentErrorCode::SendCustomMetricInvalidOccurredAt,
            ));
        }
    };

    let usecase = CustomMetricUsecase::new();
    match usecase
        .save(CustomMetricStoreRequest {
            key: json.key,
            value: json.value,
            occurred_at,
        })
        .await
    {
        Ok(_) => {
            log::info!("sent custom metrics");
            Ok(HttpResponse::NoContent().finish())
        }
        Err(e) => {
            log::error!("{:?}", e);
            Ok(create_agent_error(AgentErrorCode::SendCustomMetricInternal))
        }
    }
}
