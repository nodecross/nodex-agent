use super::utils::milliseconds_to_time;
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
    occurred_at: u64,
}

pub async fn handler(
    _req: HttpRequest,
    web::Json(json): web::Json<Vec<MessageContainer>>,
) -> actix_web::Result<HttpResponse, AgentError> {
    let metrics = json
        .iter()
        .map(|m| {
            if m.key.is_empty() {
                return Err(AgentErrorCode::SendCustomMetricNoKey);
            }

            let occurred_at = milliseconds_to_time(m.occurred_at)
                .ok_or(AgentErrorCode::SendCustomMetricInvalidOccurredAt)?;

            Ok(CustomMetricStoreRequest {
                key: m.key.clone(),
                value: m.value,
                occurred_at,
            })
        })
        .collect::<Result<Vec<CustomMetricStoreRequest>, AgentErrorCode>>()
        .map_err(AgentError::new)?;

    let usecase = CustomMetricUsecase::new();
    match usecase.save(metrics).await {
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
