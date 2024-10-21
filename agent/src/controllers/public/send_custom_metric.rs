use super::utils::str2time;
use actix_web::{web, HttpRequest, HttpResponse};

use serde::{Deserialize, Serialize};

use crate::{
    errors::{AgentError, AgentErrorCode},
    repository::custom_metric_repository::CustomMetricStoreRequest,
    usecase::custom_metric_usecase::CustomMetricUsecase,
};

#[derive(Deserialize, Serialize)]
pub struct MessageContainer {
    #[serde(default)]
    key: String,
    value: f32,
    #[serde(default)]
    occurred_at: String,
}

pub async fn handler(
    _req: HttpRequest,
    web::Json(json): web::Json<MessageContainer>,
) -> actix_web::Result<HttpResponse, AgentError> {
    if json.key.is_empty() {
        Err(AgentErrorCode::SendCustomMetricNoKey)?
    }

    let occurred_at =
        str2time(&json.occurred_at).ok_or(AgentErrorCode::SendCustomMetricInvalidOccurredAt)?;

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
            Err(AgentErrorCode::SendCustomMetricInternal)?
        }
    }
}
