use actix_web::{web, HttpRequest, HttpResponse};
use serde::{Deserialize, Serialize};

use crate::{
    errors::{create_agent_error, AgentErrorCode},
    repository::attribute_repository::AttributeStoreRequest,
    usecase::attribute_usecase::AttributeUsecase,
};

#[derive(Deserialize, Serialize)]
pub struct MessageContainer {
    key_name: String,
    value: String,
}

pub async fn handler(
    _req: HttpRequest,
    web::Json(json): web::Json<MessageContainer>,
) -> actix_web::Result<HttpResponse> {
    if json.key_name.is_empty() {
        return Ok(create_agent_error(AgentErrorCode::SendAttributeNoKeyName));
    }
    if json.value.is_empty() {
        return Ok(create_agent_error(AgentErrorCode::SendAttributeNoValue));
    }

    let usecase = AttributeUsecase::new();
    match usecase
        .save(AttributeStoreRequest {
            key_name: json.key_name,
            value: json.value,
        })
        .await
    {
        Ok(_) => {
            log::info!("save attribute");
            Ok(HttpResponse::NoContent().finish())
        }
        Err(e) => {
            log::error!("{:?}", e);
            Ok(create_agent_error(AgentErrorCode::SendAttributeInternal))
        }
    }
}
