use super::utils::milliseconds_to_time;
use crate::{
    controllers::errors::AgentErrorCode,
    usecase::custom_metric_usecase::CustomMetricUsecase,
};
use axum::extract::Json;
use axum::http::StatusCode;
use protocol::cbor::types::{CustomMetric, TimeValue};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Deserialize, Serialize)]
pub struct MessageContainer {
    #[serde(default)]
    key: String,
    value: f32,
    #[serde(default)]
    occurred_at: u64,
}

pub async fn handler(
    Json(json): Json<Vec<MessageContainer>>,
) -> Result<StatusCode, AgentErrorCode> {
    let metrics: Vec<CustomMetric> = json
        .into_iter()
        .try_fold(
            HashMap::new(),
            |mut acc: HashMap<String, Vec<TimeValue>>,
             MessageContainer {
                 key,
                 value,
                 occurred_at,
             }| {
                if key.is_empty() {
                    return Err(AgentErrorCode::SendCustomMetricNoKey);
                }
                let occurred_at = milliseconds_to_time(occurred_at)
                    .ok_or(AgentErrorCode::SendCustomMetricInvalidOccurredAt)?;
                acc.entry(key)
                    .or_default()
                    .push(TimeValue(occurred_at, value));
                Ok(acc)
            },
        )?
        .into_iter()
        .map(|(typ, values)| CustomMetric { typ, values })
        .collect();

    let usecase = CustomMetricUsecase::new();
    match usecase.save(metrics).await {
        Ok(_) => {
            log::info!("sent custom metrics");
            Ok(StatusCode::NO_CONTENT)
        }
        Err(e) => {
            log::error!("{:?}", e);
            Err(AgentErrorCode::SendCustomMetricInternal)?
        }
    }
}
