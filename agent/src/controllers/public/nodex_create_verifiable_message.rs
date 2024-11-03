use actix_web::{web, HttpRequest, HttpResponse};
use chrono::Utc;
use serde::{Deserialize, Serialize};

use crate::errors::{AgentError, AgentErrorCode};
use crate::nodex::utils::did_accessor::DidAccessorImpl;
use crate::usecase::verifiable_message_usecase::CreateVerifiableMessageUseCaseError as U;
use crate::{
    services::studio::Studio, usecase::verifiable_message_usecase::VerifiableMessageUseCase,
};

use super::utils;

// NOTE: POST /create-verifiable-message
#[derive(Deserialize, Serialize)]
pub struct MessageContainer {
    #[serde(default)]
    destination_did: String,
    #[serde(default)]
    message: String,
    #[serde(default)]
    operation_tag: String,
}

pub async fn handler(
    _req: HttpRequest,
    web::Json(json): web::Json<MessageContainer>,
) -> actix_web::Result<HttpResponse, AgentError> {
    if json.destination_did.is_empty() {
        Err(AgentErrorCode::CreateVerifiableMessageNoDestinationDid)?
    }
    if json.message.is_empty() {
        Err(AgentErrorCode::CreateVerifiableMessageNoMessage)?
    }
    if json.operation_tag.is_empty() {
        Err(AgentErrorCode::CreateVerifiableMessageNoOperationTag)?
    }
    let now = Utc::now();

    let repo = utils::did_repository();
    let usecase =
        VerifiableMessageUseCase::new(Studio::new(), repo.clone(), DidAccessorImpl {}, repo);

    match usecase
        .generate(json.destination_did, json.message, json.operation_tag, now)
        .await
    {
        Ok(v) => Ok(HttpResponse::Ok().body(v)),
        Err(e) => match e {
            U::MessageActivity(e) => Err(utils::handle_status(e)),
            U::DestinationNotFound(e) => {
                if let Some(e) = e {
                    log::error!("{:?}", e);
                }
                Err(AgentErrorCode::CreateVerifiableMessageNoTargetDid)?
            }
            U::DidVcServiceGenerate(e) => {
                log::error!("{:?}", e);
                Err(AgentErrorCode::CreateVerifiableMessageInternal)?
            }
            U::Json(e) => {
                log::warn!("json error: {}", e);
                Err(AgentErrorCode::CreateVerifiableMessageInternal)?
            }
        },
    }
}
