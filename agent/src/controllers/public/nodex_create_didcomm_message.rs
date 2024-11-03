use actix_web::{web, HttpRequest, HttpResponse};
use chrono::Utc;
use serde::{Deserialize, Serialize};

use protocol::didcomm::encrypted::DidCommEncryptedServiceGenerateError as S;

use crate::errors::{AgentError, AgentErrorCode};
use crate::nodex::utils::did_accessor::DidAccessorImpl;
use crate::usecase::didcomm_message_usecase::GenerateDidcommMessageUseCaseError as U;
use crate::{services::studio::Studio, usecase::didcomm_message_usecase::DidcommMessageUseCase};

use super::utils;

// NOTE: POST /create-didcomm-message
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
        Err(AgentErrorCode::CreateDidCommMessageNoDestinationDid)?
    }
    if json.message.is_empty() {
        Err(AgentErrorCode::CreateDidCommMessageNoMessage)?
    }
    if json.operation_tag.is_empty() {
        Err(AgentErrorCode::CreateDidCommMessageNoOperationTag)?
    }

    let now = Utc::now();

    let usecase =
        DidcommMessageUseCase::new(Studio::new(), utils::did_repository(), DidAccessorImpl {});

    match usecase
        .generate(json.destination_did, json.message, json.operation_tag, now)
        .await
    {
        Ok(v) => Ok(HttpResponse::Ok().body(v)),
        Err(e) => match e {
            U::MessageActivity(e) => Err(utils::handle_status(e)),
            U::ServiceGenerate(S::DidDocNotFound(target)) => {
                log::warn!("target DID not found. did = {}", target);
                Err(AgentErrorCode::CreateDidCommMessageNoDid)?
            }
            U::ServiceGenerate(S::DidPublicKeyNotFound(e)) => {
                log::warn!("cannot find public key: {}", e);
                Err(AgentErrorCode::CreateDidCommMessageNoPubKey)?
            }
            U::Json(e) | U::ServiceGenerate(S::Json(e)) => {
                log::warn!("json error: {}", e);
                Err(AgentErrorCode::CreateDidcommMessageInternal)?
            }
            U::ServiceGenerate(S::VcService(e)) => {
                log::warn!("verify failed: {}", e);
                Err(AgentErrorCode::CreateDidCommMessageVerifyFailed)?
            }
            U::ServiceGenerate(S::SidetreeFindRequestFailed(e)) => {
                log::warn!("sidetree error: {}", e);
                Err(AgentErrorCode::CreateDidcommMessageInternal)?
            }
            U::ServiceGenerate(S::EncryptFailed(e)) => {
                log::warn!("decrypt failed: {}", e);
                Err(AgentErrorCode::CreateDidcommMessageInternal)?
            }
        },
    }
}
