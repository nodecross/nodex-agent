use actix_web::{HttpRequest, HttpResponse};
use serde::{Deserialize, Serialize};

// NOTE: POST /identifiers
#[derive(Deserialize, Serialize)]
struct MessageContainer {}

pub async fn handler(_req: HttpRequest) -> actix_web::Result<HttpResponse> {
    let service = crate::services::nodex::NodeX::new();

    match service.create_identifier().await {
        Ok(v) => Ok(HttpResponse::Ok().json(&v)),
        Err(e) => {
            log::error!("{:?}", e);
            Ok(HttpResponse::InternalServerError().finish())
        }
    }
}
