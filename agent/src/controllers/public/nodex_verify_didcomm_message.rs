use actix_web::{web, HttpRequest, HttpResponse};
use chrono::Utc;
use serde::{Deserialize, Serialize};

use protocol::didcomm::encrypted::DidCommEncryptedServiceVerifyError as S;
use protocol::didcomm::types::DidCommMessage;

use crate::errors::{create_agent_error, AgentError, AgentErrorCode};
use crate::nodex::utils::did_accessor::DidAccessorImpl;
use crate::{
    services::studio::Studio,
    usecase::didcomm_message_usecase::{
        DidcommMessageUseCase, VerifyDidcommMessageUseCaseError as U,
    },
};

use super::utils;

// NOTE: POST /verify-verifiable-message
#[derive(Deserialize, Serialize)]
pub struct MessageContainer {
    message: String,
}

pub async fn handler(
    _req: HttpRequest,
    web::Json(json): web::Json<MessageContainer>,
) -> actix_web::Result<HttpResponse> {
    let now = Utc::now();

    let usecase =
        DidcommMessageUseCase::new(Studio::new(), utils::did_repository(), DidAccessorImpl {});

    match serde_json::from_str::<DidCommMessage>(&json.message) {
        Err(e) => Ok(HttpResponse::BadRequest().body(e.to_string())),
        Ok(message) => match usecase.verify(message, now).await {
            Ok(v) => Ok(HttpResponse::Ok().json(v)),
            Err(e) => match e {
                U::MessageActivity(e) => Ok(utils::handle_status(e)),
                U::NotAddressedToMe => {
                    log::warn!("this message is not addressed to me: {}", e);
                    Ok(create_agent_error(
                        AgentErrorCode::VerifyDidcommMessageNotAddressedToMe,
                    ))
                }
                U::ServiceVerify(S::FindSender(e)) => {
                    log::warn!("cannot find sender: {}", e);
                    Ok(create_agent_error(
                        AgentErrorCode::VerifyDidcommMessageNoSender,
                    ))
                }
                U::ServiceVerify(S::DidPublicKeyNotFound(e)) => {
                    log::warn!("cannot find public key: {}", e);
                    Ok(create_agent_error(
                        AgentErrorCode::VerifyDidcommMessageNoPublicKey,
                    ))
                }
                U::ServiceVerify(S::MetadataBodyNotFound(e)) => {
                    let e = e.map(|e| e.to_string()).unwrap_or("".to_string());
                    log::warn!("cannot find metadata: {}", e);
                    Ok(create_agent_error(
                        AgentErrorCode::VerifyDidcommMessageNoMetadata,
                    ))
                }
                U::ServiceVerify(S::VcService(e)) => {
                    log::warn!("verify failed: {}", e);
                    Ok(create_agent_error(
                        AgentErrorCode::VerifyDidcommMessageVerifyFailed,
                    ))
                }
                U::ServiceVerify(S::DidDocNotFound(target)) => {
                    log::warn!("target DID not found. DID = {}", target);
                    Ok(create_agent_error(
                        AgentErrorCode::VerifyDidcommMessageNoTargetDid,
                    ))
                }
                U::Json(e) | U::ServiceVerify(S::Json(e)) => {
                    log::warn!("json error: {}", e);
                    Ok(create_agent_error(
                        AgentErrorCode::VerifyDidcommMessageInternal,
                    ))
                }
                U::ServiceVerify(S::DecryptFailed(e)) => {
                    log::warn!("decrypt failed: {}", e);
                    Ok(create_agent_error(
                        AgentErrorCode::VerifyDidcommMessageInternal,
                    ))
                }
                U::ServiceVerify(S::SidetreeFindRequestFailed(e)) => {
                    log::warn!("sidetree error: {}", e);
                    Ok(create_agent_error(
                        AgentErrorCode::VerifyDidcommMessageInternal,
                    ))
                }
            },
        },
    }
}
