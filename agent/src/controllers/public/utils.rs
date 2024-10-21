use actix_web::HttpResponse;
use anyhow::Context as _;

use protocol::did::did_repository::DidRepositoryImpl;

use crate::errors::{create_agent_error, AgentErrorCode};
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
            create_agent_error(AgentErrorCode::MessageActivityBadRequest)
        }
        MessageActivityHttpError::Forbidden(message) => {
            log::warn!("Forbidden: {}", message);
            create_agent_error(AgentErrorCode::MessageActivityForbidden)
        }
        MessageActivityHttpError::Unauthorized(message) => {
            log::warn!("Unauthorized: {}", message);
            create_agent_error(AgentErrorCode::MessageActivityUnauthorized)
        }
        MessageActivityHttpError::NotFound(message) => {
            log::warn!("Not Found: {}", message);
            create_agent_error(AgentErrorCode::MessageActivityNotFound)
        }
        MessageActivityHttpError::Conflict(message) => {
            log::warn!("Conflict: {}", message);
            create_agent_error(AgentErrorCode::MessageActivityConflict)
        }
        _ => create_agent_error(AgentErrorCode::MessageActivityInternal),
    }
}
