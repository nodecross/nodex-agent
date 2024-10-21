use actix_web::{web, HttpRequest, HttpResponse};
use serde::{Deserialize, Serialize};

use crate::{
    errors::{AgentError, AgentErrorCode},
    repository::attribute_repository::AttributeStoreRequest,
    usecase::attribute_usecase::AttributeUsecase,
};

#[derive(Deserialize, Serialize)]
pub struct MessageContainer {
    #[serde(default)]
    key_name: String,
    #[serde(default)]
    value: String,
}

pub async fn handler(
    _req: HttpRequest,
    web::Json(json): web::Json<MessageContainer>,
) -> actix_web::Result<HttpResponse, AgentError> {
    if json.key_name.is_empty() {
        Err(AgentErrorCode::SendAttributeNoKeyName)?
    }
    if json.value.is_empty() {
        Err(AgentErrorCode::SendAttributeNoValue)?
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
            Err(AgentErrorCode::SendAttributeInternal)?
        }
    }
}
