use actix_web::{web, HttpRequest, HttpResponse};
use chrono::Utc;
use nodex_didcomm::didcomm::encrypted::DIDCommEncryptedService;
use serde::{Deserialize, Serialize};

use crate::{services::hub::Hub, usecase::didcomm_message_usecase::DidcommMessageUseCase};
use crate::{
    services::{nodex::NodeX, project_verifier::ProjectVerifierImplOnNetworkConfig},
    usecase::didcomm_message_usecase::GenerateDidcommMessageUseCaseError,
};

use super::{get_my_did, get_my_keyring};

// NOTE: POST /create-didcomm-message
#[derive(Deserialize, Serialize)]
pub struct MessageContainer {
    destination_did: String,
    message: String,
    operation_tag: String,
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

    match usecase
        .generate(json.destination_did, json.message, json.operation_tag, now)
        .await
    {
        Ok(v) => Ok(HttpResponse::Ok().body(v)),
        Err(e) => match e {
            GenerateDidcommMessageUseCaseError::TargetDidNotFound(target) => {
                log::warn!("Target DID not found. did = {}", target);
                Ok(HttpResponse::NotFound().finish())
            }
            GenerateDidcommMessageUseCaseError::BadRequest(message) => {
                log::warn!("Bad Request: {}", message);
                Ok(HttpResponse::BadRequest().body(message))
            }
            GenerateDidcommMessageUseCaseError::Unauthorized(message) => {
                log::warn!("Unauthorized: {}", message);
                Ok(HttpResponse::Unauthorized().body(message))
            }
            GenerateDidcommMessageUseCaseError::Forbidden(message) => {
                log::warn!("Forbidden: {}", message);
                Ok(HttpResponse::Forbidden().body(message))
            }
            GenerateDidcommMessageUseCaseError::NotFound(message) => {
                log::warn!("Not Found: {}", message);
                Ok(HttpResponse::NotFound().body(message))
            }
            GenerateDidcommMessageUseCaseError::Conflict(message) => {
                log::warn!("Conflict: {}", message);
                Ok(HttpResponse::Conflict().body(message))
            }
            GenerateDidcommMessageUseCaseError::Other(e) => {
                log::error!("{:?}", e);
                Ok(HttpResponse::InternalServerError().finish())
            }
        },
    }
}
