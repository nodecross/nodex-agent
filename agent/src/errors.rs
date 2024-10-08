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
    #[error("verify failed")]
    CreateDidCommMessageVerifyFailed = 3001,
    #[error("target DID not found")]
    CreateDidCommMessageNoDid = 4001,
    #[error("Internal Server Error")]
    NetworkInternal = 5001,
    #[error("Internal Server Error")]
    VersionInternal = 5002,
    #[error("Internal Server Error")]
    CreateDidCommMessageInternal = 5003,
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
        } else {
            HttpResponse::InternalServerError().json(error)
        }
    }
}
pub fn create_agent_error(code: AgentErrorCode) -> HttpResponse {
    AgentError::new(code).into()
}
