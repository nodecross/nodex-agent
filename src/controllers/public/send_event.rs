use actix_web::{web, HttpRequest, HttpResponse};
use chrono::DateTime;
use serde::{Deserialize, Serialize};

use crate::{
    repository::event_repository::EventStoreRequest, usecase::event_usecase::EventUsecase,
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
        return Ok(HttpResponse::BadRequest().json("key is required"));
    }
    if json.detail.is_empty() {
        return Ok(HttpResponse::BadRequest().json("detail is required"));
    }

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
            Ok(HttpResponse::InternalServerError().json("internal server error"))
        }
    }
}
