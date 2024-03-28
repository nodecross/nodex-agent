use actix_web::{web, HttpRequest, HttpResponse};
use chrono::Utc;
use nodex_didcomm::didcomm::encrypted::DIDCommEncryptedService;
use serde::{Deserialize, Serialize};

use crate::services::{nodex::NodeX, project_verifier::ProjectVerifierImplOnNetworkConfig};
use crate::{
    services::hub::Hub,
    usecase::didcomm_message_usecase::{DidcommMessageUseCase, VerifyDidcommMessageUseCaseError},
};

use super::{get_my_did, get_my_keyring};

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

    let my_did = get_my_did();
    let my_keyring = get_my_keyring();

    let usecase = DidcommMessageUseCase::new(
        ProjectVerifierImplOnNetworkConfig::new(),
        Hub::new(),
        DIDCommEncryptedService::new(NodeX::new(), None),
        my_did,
        my_keyring,
    );

    match usecase.verify(&json.message, now).await {
        Ok(v) => Ok(HttpResponse::Ok().json(v)),
        Err(e) => match e {
            VerifyDidcommMessageUseCaseError::VerificationFailed => {
                Ok(HttpResponse::Unauthorized().finish())
            }
            VerifyDidcommMessageUseCaseError::TargetDidNotFound(target) => {
                log::warn!("Target DID not found. did = {}", target);
                Ok(HttpResponse::NotFound().finish())
            }
            VerifyDidcommMessageUseCaseError::BadRequest(message) => {
                log::warn!("Bad Request: {}", message);
                Ok(HttpResponse::BadRequest().body(message))
            }
            VerifyDidcommMessageUseCaseError::Unauthorized(message) => {
                log::warn!("Unauthorized: {}", message);
                Ok(HttpResponse::Unauthorized().body(message))
            }
            VerifyDidcommMessageUseCaseError::Forbidden(message) => {
                log::warn!("Forbidden: {}", message);
                Ok(HttpResponse::Forbidden().body(message))
            }
            VerifyDidcommMessageUseCaseError::NotFound(message) => {
                log::warn!("Not Found: {}", message);
                Ok(HttpResponse::NotFound().body(message))
            }
            VerifyDidcommMessageUseCaseError::Conflict(message) => {
                log::warn!("Conflict: {}", message);
                Ok(HttpResponse::Conflict().body(message))
            }
            VerifyDidcommMessageUseCaseError::Other(e) => {
                log::error!("{:?}", e);
                Ok(HttpResponse::InternalServerError().finish())
            }
        },
    }
}
