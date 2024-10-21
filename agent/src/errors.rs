use actix_web::HttpResponse;
use serde::Serialize;
use std::convert::From;
use thiserror::Error;

#[derive(Serialize, Clone, Copy, Debug, Error)]
pub enum AgentErrorCode {
    #[error("binary_url is required")]
    VersionNoBinaryUrl = 1001,
    #[error("path is required")]
    VersionNoPath = 1002,
    #[error("cannot find public key")]
    CreateDidCommMessageNoPubKey = 1003,
    #[error("sender not found")]
    VerifyDidcommMessageNoSender = 1005,
    #[error("public key not found")]
    VerifyDidcommMessageNoPublicKey = 1004,
    #[error("metadata not found")]
    VerifyDidcommMessageNoMetadata = 1006,
    #[error("json error")]
    VerifyDidcommMessageJsonError = 1007,
    #[error("public key not found")]
    VerifyVerifiableMessageNoPublicKey = 1008,
    #[error("json error")]
    VerifyVerifiableMessageJsonError = 1009,
    #[error("key_name is required")]
    SendAttributeNoKeyName = 1010,
    #[error("value is required")]
    SendAttributeNoValue = 1011,
    #[error("key is required")]
    SendCustomMetricNoKey = 1012,
    #[error("occurred_at is invalid format")]
    SendCustomMetricInvalidOccurredAt = 1013,
    #[error("key is invalid")]
    SendEventNoKey = 1014,
    #[error("detail is invalid")]
    SendEventNoDetail = 1015,
    #[error("occurred_at is invalid format")]
    SendEventInvalidOccurredAt = 1016,
    #[error("Bad Request")]
    MessageActivityBadRequest = 1017,

    #[error("this message is not addressed to me")]
    VerifyDidcommMessageNotAddressedToMe = 2001,
    #[error("this message is not addressed to me")]
    VerifyVerifiableMessageNotAddressedToMe = 2002,
    #[error("Forbidden")]
    MessageActivityForbidden = 2003,

    #[error("verify failed")]
    CreateDidCommMessageVerifyFailed = 3001,
    #[error("verify failed")]
    VerifyDidcommMessageVerifyFailed = 3002,
    #[error("verify failed")]
    VerifyVerifiableMessageVerifyFailed = 3003,
    #[error("Unauthorized")]
    MessageActivityUnauthorized = 3004,

    #[error("target DID not found")]
    CreateDidCommMessageNoDid = 4001,
    #[error("target DID not found")]
    CreateVerifiableMessageNoTargetDid = 4002,
    #[error("target DID not found")]
    VerifyDidcommMessageNoTargetDid = 4003,
    #[error("identifier not found")]
    VerifyVerifiableMessageNoIdentifier = 4004,
    #[error("target DID not found")]
    VerifyVerifiableMessageNoTargetDid = 4005,
    #[error("Not Found")]
    MessageActivityNotFound = 4006,

    #[error("Internal Server Error")]
    NetworkInternal = 5001,
    #[error("Internal Server Error")]
    VersionInternal = 5002,
    #[error("Internal Server Error")]
    CreateDidcommMessageInternal = 5003,
    #[error("Internal Server Error")]
    CreateIdentifierInternal = 5004,
    #[error("Internal Server Error")]
    CreateVerifiableMessageInternal = 5005,
    #[error("Internal Server Error")]
    FindIdentifierInternal = 5006,
    #[error("Internal Server Error")]
    VerifyDidcommMessageInternal = 5007,
    #[error("Internal Server Error")]
    VerifyVerifiableMessageInternal = 5008,
    #[error("Internal Server Error")]
    SendAttributeInternal = 5009,
    #[error("Internal Server Error")]
    SendCustomMetricInternal = 5010,
    #[error("Internal Server Error")]
    SendEventInternal = 5011,
    #[error("Internal Server Error")]
    MessageActivityInternal = 5012,

    #[error("Conflict")]
    MessageActivityConflict = 6001,
}

#[derive(Serialize)]
pub struct AgentError {
    code: AgentErrorCode,
    message: String,
}

impl AgentError {
    pub fn new(code: AgentErrorCode) -> Self {
        Self {
            code,
            message: format!("{}", code),
        }
    }
}
impl From<AgentError> for HttpResponse {
    fn from(error: AgentError) -> Self {
        let code = error.code as u16;
        if (1000..2000).contains(&code) {
            HttpResponse::BadRequest().json(error)
        } else if (2000..3000).contains(&code) {
            HttpResponse::Forbidden().json(error)
        } else if (3000..4000).contains(&code) {
            HttpResponse::Unauthorized().json(error)
        } else if (4000..5000).contains(&code) {
            HttpResponse::NotFound().json(error)
        } else if (5000..6000).contains(&code) {
            HttpResponse::InternalServerError().json(error)
        } else if (6000..6100).contains(&code) {
            HttpResponse::Conflict().json(error)
        } else {
            HttpResponse::InternalServerError().json(error)
        }
    }
}
pub fn create_agent_error(code: AgentErrorCode) -> HttpResponse {
    AgentError::new(code).into()
}
