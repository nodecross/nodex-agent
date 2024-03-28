use actix_web::{web, HttpRequest, HttpResponse};
use chrono::Utc;

use nodex_didcomm::verifiable_credentials::did_vc::DIDVCService;
use serde::{Deserialize, Serialize};

use crate::{services::hub::Hub, usecase::verifiable_message_usecase::VerifiableMessageUseCase};
use crate::{
    services::{nodex::NodeX, project_verifier::ProjectVerifierImplOnNetworkConfig},
    usecase::verifiable_message_usecase::CreateVerifiableMessageUseCaseError,
};

use super::{get_my_did, get_my_keyring};

// NOTE: POST /create-verifiable-message
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

    let usecase = VerifiableMessageUseCase::new(
        Box::new(ProjectVerifierImplOnNetworkConfig::new()),
        Box::new(NodeX::new()),
        Box::new(Hub::new()),
        DIDVCService::new(NodeX::new()),
        my_did,
        my_keyring,
    );

    match usecase
        .generate(json.destination_did, json.message, json.operation_tag, now)
        .await
    {
        Ok(v) => Ok(HttpResponse::Ok().body(v)),
        Err(e) => match e {
            CreateVerifiableMessageUseCaseError::DestinationNotFound => {
                Ok(HttpResponse::NotFound().finish())
            }
            CreateVerifiableMessageUseCaseError::BadRequest(message) => {
                log::warn!("Bad Request: {}", message);
                Ok(HttpResponse::BadRequest().body(message))
            }
            CreateVerifiableMessageUseCaseError::Unauthorized(message) => {
                log::warn!("Unauthorized: {}", message);
                Ok(HttpResponse::Unauthorized().body(message))
            }
            CreateVerifiableMessageUseCaseError::Forbidden(message) => {
                log::warn!("Forbidden: {}", message);
                Ok(HttpResponse::Forbidden().body(message))
            }
            CreateVerifiableMessageUseCaseError::NotFound(message) => {
                log::warn!("NotFound: {}", message);
                Ok(HttpResponse::NotFound().body(message))
            }
            CreateVerifiableMessageUseCaseError::Conflict(message) => {
                log::warn!("Conflict: {}", message);
                Ok(HttpResponse::Conflict().body(message))
            }
            CreateVerifiableMessageUseCaseError::VCServiceFailed(e) => {
                log::error!("{:?}", e);
                Ok(HttpResponse::InternalServerError().finish())
            }
            CreateVerifiableMessageUseCaseError::Other(e) => {
                log::error!("{:?}", e);
                Ok(HttpResponse::InternalServerError().finish())
            }
        },
    }
}
