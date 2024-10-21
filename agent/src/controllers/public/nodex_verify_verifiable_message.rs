use actix_web::{web, HttpRequest, HttpResponse};
use chrono::Utc;
use serde::{Deserialize, Serialize};

use protocol::verifiable_credentials::did_vc::DidVcServiceVerifyError as S;
use protocol::verifiable_credentials::types::VerifiableCredentials;

use crate::errors::{create_agent_error, AgentErrorCode};
use crate::nodex::utils::did_accessor::DidAccessorImpl;
use crate::usecase::verifiable_message_usecase::VerifyVerifiableMessageUseCaseError as U;
use crate::{
    services::studio::Studio, usecase::verifiable_message_usecase::VerifiableMessageUseCase,
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

    let repo = utils::did_repository();
    let usecase =
        VerifiableMessageUseCase::new(Studio::new(), repo.clone(), DidAccessorImpl {}, repo);

    match serde_json::from_str::<VerifiableCredentials>(&json.message) {
        Err(e) => {
            log::warn!("json error: {}", e);
            Ok(create_agent_error(
                AgentErrorCode::VerifyVerifiableMessageJsonError,
            ))
        }
        Ok(vc) => match usecase.verify(vc, now).await {
            Ok(v) => Ok(HttpResponse::Ok().json(v)),
            Err(e) => match e {
                U::MessageActivity(e) => Ok(utils::handle_status(e)),
                U::DidVcServiceVerify(S::VerifyFailed(e)) => {
                    log::warn!("verify failed: {}", e);
                    Ok(create_agent_error(
                        AgentErrorCode::VerifyVerifiableMessageVerifyFailed,
                    ))
                }
                U::DidVcServiceVerify(S::FindIdentifier(e)) => {
                    log::warn!("find identifier error: {}", e);
                    Ok(create_agent_error(
                        AgentErrorCode::VerifyVerifiableMessageNoIdentifier,
                    ))
                }
                U::DidVcServiceVerify(S::DidDocNotFound(target)) => {
                    log::warn!("target DID not found. DID = {}", target);
                    Ok(create_agent_error(
                        AgentErrorCode::VerifyVerifiableMessageNoTargetDid,
                    ))
                }
                U::NotAddressedToMe => {
                    log::warn!("this message is not addressed to me: {}", e);
                    Ok(create_agent_error(
                        AgentErrorCode::VerifyVerifiableMessageNotAddressedToMe,
                    ))
                }
                U::Json(e) => {
                    log::warn!("json error: {}", e);
                    Ok(create_agent_error(
                        AgentErrorCode::VerifyVerifiableMessageInternal,
                    ))
                }
                U::DidVcServiceVerify(S::PublicKeyNotFound(e)) => {
                    log::warn!("cannot find public key: {}", e);
                    Ok(create_agent_error(
                        AgentErrorCode::VerifyVerifiableMessageNoPublicKey,
                    ))
                }
            },
        },
    }
}
