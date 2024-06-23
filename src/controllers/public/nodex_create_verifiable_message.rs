use actix_web::{web, HttpRequest, HttpResponse};
use chrono::Utc;
use serde::{Deserialize, Serialize};

use crate::nodex::utils::did_accessor::DIDAccessorImpl;
use crate::{
    services::project_verifier::ProjectVerifierImplOnNetworkConfig,
    usecase::verifiable_message_usecase::CreateVerifiableMessageUseCaseError,
};
use crate::{
    services::{nodex::NodeX, studio::Studio},
    usecase::verifiable_message_usecase::VerifiableMessageUseCase,
};
use nodex_didcomm::verifiable_credentials::did_vc::DIDVCService;

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

    let usecase = VerifiableMessageUseCase::new(
        Box::new(ProjectVerifierImplOnNetworkConfig::new()),
        Box::new(NodeX::new()),
        Box::new(Studio::new()),
        DIDVCService::new(NodeX::new()),
        Box::new(DIDAccessorImpl {}),
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
