use crate::services::nodex::NodeX;
use actix_web::{web, HttpRequest, HttpResponse};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::path::PathBuf;

// NOTE: POST /internal/version
#[derive(Deserialize, Serialize)]
pub struct MessageContainer {
    message: Value,
}

pub async fn handler_get(_req: HttpRequest) -> actix_web::Result<HttpResponse> {
    let current_version = env!("CARGO_PKG_VERSION");
    Ok(HttpResponse::Ok().json(&json!({ "version": current_version })))
}

pub async fn handler_update(
    _req: HttpRequest,
    web::Json(json): web::Json<MessageContainer>,
) -> actix_web::Result<HttpResponse> {
    let binary_url = match json.message["binary_url"].as_str() {
        Some(url) => url,
        None => return Ok(HttpResponse::BadRequest().json("binary_url is required")),
    };
    let path = match json.message["path"].as_str() {
        Some(p) => p,
        None => return Ok(HttpResponse::BadRequest().json("path is required")),
    };
    let nodex = NodeX::new();
    match nodex.update_version(binary_url, PathBuf::from(path)).await {
        Ok(_) => Ok(HttpResponse::Ok().json("ok")),
        Err(_) => Ok(HttpResponse::InternalServerError().finish()),
    }
}
