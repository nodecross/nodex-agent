use actix_web::{web, HttpRequest, HttpResponse};
use chrono::DateTime;
use serde::{Deserialize, Serialize};

use crate::{
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
    let occurred_at = match json.occurred_at.parse::<i64>() {
        Ok(timestamp) => match DateTime::from_timestamp(timestamp, 0) {
            Some(dt) => dt,
            _ => {
                return Ok(HttpResponse::BadRequest().json("occurred_at is invalid format"));
            }
        },
        Err(_) => {
            return Ok(HttpResponse::BadRequest().json("occurred_at is invalid format"));
        }
    };

    let usecase = CustomMetricUsecase::new();
    usecase
        .save(CustomMetricStoreRequest {
            key: json.key,
            value: json.value,
            occurred_at,
        })
        .await;
    Ok(HttpResponse::NoContent().finish())
}
