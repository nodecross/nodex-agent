use actix_web::{web, HttpRequest, HttpResponse};
use chrono::Utc;
use serde::{Deserialize, Serialize};

use protocol::verifiable_credentials::did_vc::DidVcServiceVerifyError as S;
use protocol::verifiable_credentials::types::VerifiableCredentials;

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
        Err(e) => Ok(HttpResponse::BadRequest().body(e.to_string())),
        Ok(vc) => match usecase.verify(vc, now).await {
            Ok(v) => Ok(HttpResponse::Ok().json(v)),
            Err(e) => match e {
                U::MessageActivity(e) => Ok(utils::handle_status(e)),
                U::DidVcServiceVerify(S::VerifyFailed(e)) => {
                    log::warn!("verify error: {}", e);
                    Ok(HttpResponse::Unauthorized().finish())
                }
                U::DidVcServiceVerify(S::FindIdentifier(e)) => {
                    log::warn!("find identifier error: {}", e);
                    Ok(HttpResponse::NotFound().finish())
                }
                U::DidVcServiceVerify(S::DidDocNotFound(target)) => {
                    log::warn!("Target DID not found. did = {}", target);
                    Ok(HttpResponse::NotFound().finish())
                }
                U::NotAddressedToMe => Ok(HttpResponse::Forbidden().finish()),
                U::Json(e) => {
                    log::warn!("json error: {}", e);
                    Ok(HttpResponse::InternalServerError().finish())
                }
                U::DidVcServiceVerify(S::PublicKeyNotFound(e)) => {
                    log::warn!("cannot public key: {}", e);
                    Ok(HttpResponse::BadRequest().body(e.to_string()))
                }
            },
        },
    }
}
