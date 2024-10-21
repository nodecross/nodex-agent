use actix_web::{web, HttpRequest, HttpResponse};
use serde::{Deserialize, Serialize};

use crate::errors::{create_agent_error, AgentErrorCode};

// NOTE: GET /identifiers/${ did }
#[derive(Deserialize, Serialize)]
struct MessageContainer {}

pub async fn handler(_req: HttpRequest, did: web::Path<String>) -> actix_web::Result<HttpResponse> {
    let service = crate::services::nodex::NodeX::new();

    match service.find_identifier(&did).await {
        Ok(v) => Ok(HttpResponse::Ok().json(&v)),
        Err(e) => {
            log::error!("{:?}", e);
            Ok(create_agent_error(AgentErrorCode::FindIdentifierInternal))
        }
    }
}
