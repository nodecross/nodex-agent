use crate::{server::Context, services::hub::Hub};
use actix_web::{web, HttpRequest, HttpResponse};
use serde::{Deserialize, Serialize};
use serde_json::Value;

// NOTE: POST /transfer
#[derive(Deserialize, Serialize)]
pub struct RequestContainer {
    destinations: Vec<String>,
    messages: Vec<Value>,
    metadata: Option<Value>,
}

#[derive(Deserialize, Serialize)]
pub struct Result {
    destination: String,
    success: bool,
    errors: Vec<String>,
}

#[derive(Deserialize, Serialize)]
pub struct ResponseContainer {
    results: Vec<Result>,
}

pub async fn handler(
    _req: HttpRequest,
    web::Json(json): web::Json<RequestContainer>,
    _context: web::Data<Context>,
) -> actix_web::Result<HttpResponse> {
    // NOTE: We will provide an update soon to allow multiple destinations.
    if json.destinations.len() != 1 {
        return Ok(HttpResponse::InternalServerError().finish());
    }

    let to_did = match json.destinations.first() {
        Some(v) => v,
        _ => return Ok(HttpResponse::InternalServerError().finish()),
    };

    // FIXME Implement both HTTP and MQTT transfer
    match Hub::new()
        .send_message(
            to_did,
            &serde_json::json!(json.messages),
            json.metadata.as_ref(),
        )
        .await
    {
        Ok(_) => Ok(HttpResponse::Ok().json(&ResponseContainer {
            results: vec![Result {
                destination: to_did.clone(),
                errors: vec![],
                success: true,
            }],
        })),
        Err(e) => {
            log::error!("{:?}", e);
            Ok(HttpResponse::InternalServerError().finish())
        }
    }
}
