use actix_web::HttpResponse;
use serde::Serialize;

#[derive(Serialize, Clone, Copy)]
pub enum AgentErrorCode {
    VersionNoBinaryUrl = 1001,
    VersionNoPath = 1002,
    NetworkInternal = 5001,
    VersionInternal = 5002,
}

#[derive(Serialize)]
pub struct AgentError {
    code: AgentErrorCode,
    message: String,
}

impl AgentError {
    pub fn new(code: AgentErrorCode, message: &str) -> Self {
        Self {
            code,
            message: message.to_string(),
        }
    }
    pub fn to_response(&self) -> HttpResponse {
        let code = self.code as u16;
        if (1000..2000).contains(&code) {
            HttpResponse::BadRequest().json(self)
        } else if (2000..3000).contains(&code) {
            HttpResponse::Forbidden().json(self)
        } else if (3000..4000).contains(&code) {
            HttpResponse::Unauthorized().json(self)
        } else if (4000..5000).contains(&code) {
            HttpResponse::NotFound().json(self)
        } else {
            HttpResponse::InternalServerError().json(self)
        }
    }
}

pub fn create_agent_error(code: AgentErrorCode, message: &str) -> HttpResponse {
    AgentError::new(code, message).to_response()
}
