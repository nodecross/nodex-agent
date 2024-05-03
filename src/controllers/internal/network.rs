use crate::services::studio::Studio;
use actix_web::{web, HttpRequest, HttpResponse};
use serde::{Deserialize, Serialize};
use serde_json::Value;

// NOTE: POST /internal/version
#[derive(Deserialize, Serialize)]
pub struct MessageContainer {
    message: Value,
}

pub async fn handler(
    _req: HttpRequest,
    web::Json(_): web::Json<MessageContainer>,
) -> actix_web::Result<HttpResponse> {
    let studio = Studio::new();
    match studio.network().await {
        Ok(_) => Ok(HttpResponse::Ok().json("ok")),
        Err(e) => {
            log::error!("{:?}", e);
            Ok(HttpResponse::InternalServerError().json("Internal Server Error"))
        }
    }
}
