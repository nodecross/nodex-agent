use actix_web::HttpResponse;
use anyhow::Context as _;

use protocol::did::did_repository::DidRepositoryImpl;

use crate::nodex::utils::sidetree_client::SideTreeClient;
use crate::repository::message_activity_repository::MessageActivityHttpError;
use crate::server_config;

pub fn did_repository() -> DidRepositoryImpl<SideTreeClient> {
    let server_config = server_config();
    let sidetree_client = SideTreeClient::new(&server_config.did_http_endpoint())
        .context("")
        .unwrap();
    DidRepositoryImpl::new(sidetree_client)
}

pub fn handle_status(e: MessageActivityHttpError) -> HttpResponse {
    match e {
        MessageActivityHttpError::BadRequest(message) => {
            log::warn!("Bad Request: {}", message);
            HttpResponse::BadRequest().body(message)
        }
        MessageActivityHttpError::Unauthorized(message) => {
            log::warn!("Unauthorized: {}", message);
            HttpResponse::Unauthorized().body(message)
        }
        MessageActivityHttpError::Forbidden(message) => {
            log::warn!("Forbidden: {}", message);
            HttpResponse::Forbidden().body(message)
        }
        MessageActivityHttpError::NotFound(message) => {
            log::warn!("Not Found: {}", message);
            HttpResponse::NotFound().body(message)
        }
        MessageActivityHttpError::Conflict(message) => {
            log::warn!("Conflict: {}", message);
            HttpResponse::Conflict().body(message)
        }
        _ => HttpResponse::InternalServerError().finish(),
    }
}
