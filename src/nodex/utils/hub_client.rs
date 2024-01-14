use crate::network_config;
use crate::nodex::errors::NodeXError;
use chrono::{DateTime, Utc};
use hmac::{Hmac, Mac};
use reqwest::{
    header::{HeaderMap, HeaderValue},
    Proxy, Url,
};
use sha2::Sha256;

use crate::services::internal::didcomm_encrypted::DIDCommEncryptedService;
use serde_json::json;

type HmacSha256 = Hmac<Sha256>;

pub struct HubClientConfig {
    pub base_url: String,
    pub proxy: String,
}

#[derive(Clone, Debug)]
pub struct HubClient {
    pub base_url: Url,
    pub instance: reqwest::Client,
}

impl HubClient {
    pub fn new(_config: &HubClientConfig) -> Result<Self, NodeXError> {
        let url = match Url::parse(&_config.base_url.to_string()) {
            Ok(v) => v,
            Err(e) => {
                log::error!("{:?}", e);
                return Err(NodeXError {});
            }
        };

        let client = Self::build_client(&_config.proxy);

        Ok(HubClient {
            instance: client,
            base_url: url,
        })
    }

    fn build_client(proxy: &String) -> reqwest::Client {
        if proxy.is_empty() {
            return reqwest::Client::new();
        }
        reqwest::Client::builder()
            .proxy(Proxy::all(proxy).unwrap())
            .user_agent("NodeX Agent")
            .build()
            .unwrap()
    }

    fn auth_headers(&self, payload: String) -> Result<HeaderMap, NodeXError> {
        let config = network_config();
        let secret = config.inner.lock().unwrap().get_secretk_key().unwrap();
        let mut mac = match HmacSha256::new_from_slice(secret.as_bytes()) {
            Ok(v) => v,
            Err(_) => {
                return Err(NodeXError {});
            }
        };
        mac.update(payload.as_bytes());
        let signature = &hex::encode(mac.finalize().into_bytes());
        let mut headers = HeaderMap::new();
        headers.insert(
            "X-Nodex-Signature",
            HeaderValue::from_str(signature).unwrap(),
        );
        headers.insert(
            reqwest::header::CONTENT_TYPE,
            HeaderValue::from_static("application/json"),
        );
        Ok(headers)
    }

    #[allow(dead_code)]
    pub async fn get(&self, _path: &str) -> Result<reqwest::Response, NodeXError> {
        let url = self.base_url.join(_path);
        let headers = self.auth_headers("".to_string());
        if let Err(e) = headers {
            log::error!("{:?}", e);
            return Err(NodeXError {});
        }
        match self
            .instance
            .get(&url.unwrap().to_string())
            .headers(headers.unwrap())
            .send()
            .await
        {
            Ok(v) => Ok(v),
            Err(e) => {
                log::error!("{:?}", e);
                Err(NodeXError {})
            }
        }
    }

    pub async fn post(&self, path: &str, body: &str) -> Result<reqwest::Response, NodeXError> {
        let url = self.base_url.join(path);
        let headers = self.auth_headers(body.to_string());
        if let Err(e) = headers {
            log::error!("{:?}", e);
            return Err(NodeXError {});
        }
        match self
            .instance
            .post(&url.unwrap().to_string())
            .headers(headers.unwrap())
            .body(body.to_string())
            .send()
            .await
        {
            Ok(v) => Ok(v),
            Err(e) => {
                log::error!("{:?}", e);
                Err(NodeXError {})
            }
        }
    }

    pub async fn send_device_info(
        &self,
        path: &str,
        project_did: &str,
        mac_address: &str,
        version: &str,
        os: &str,
    ) -> Result<reqwest::Response, NodeXError> {
        let message = json!({
            "mac_address": mac_address,
            "version": version,
            "os": os,
        });
        let payload =
            match DIDCommEncryptedService::generate(project_did, &json!(message), None).await {
                Ok(v) => v,
                Err(e) => {
                    log::error!("{:?}", e);
                    return Err(NodeXError {});
                }
            };
        let payload = match serde_json::to_string(&payload) {
            Ok(v) => v,
            Err(e) => {
                log::error!("{:?}", e);
                return Err(NodeXError {});
            }
        };
        let url = self.base_url.join(path);
        self.post(url.unwrap().as_ref(), &payload).await
    }

    pub async fn get_message(
        &self,
        path: &str,
        project_did: &str,
    ) -> Result<reqwest::Response, NodeXError> {
        let payload =
            DIDCommEncryptedService::generate(project_did, &serde_json::Value::Null, None)
                .await?
                .to_string();
        let url = self.base_url.join(path);
        self.post(url.unwrap().as_ref(), &payload).await
    }

    pub async fn ack_message(
        &self,
        path: &str,
        project_did: &str,
        message_id: String,
        is_verified: bool,
    ) -> Result<reqwest::Response, NodeXError> {
        let url = self.base_url.join(path);
        let payload = json!({
            "message_id": message_id,
            "is_verified": is_verified,
        });
        let payload = DIDCommEncryptedService::generate(project_did, &payload, None)
            .await?
            .to_string();
        self.post(url.unwrap().as_ref(), &payload).await
    }

    pub async fn send_message(
        &self,
        path: &str,
        to_did: &str,
        message: serde_json::Value,
    ) -> Result<reqwest::Response, NodeXError> {
        let payload = DIDCommEncryptedService::generate(to_did, &message, None)
            .await?
            .to_string();
        let url = self.base_url.join(path);
        self.post(url.unwrap().as_ref(), &payload).await
    }

    pub async fn heartbeat(
        &self,
        path: &str,
        project_did: &str,
        is_active: bool,
        event_at: DateTime<Utc>,
    ) -> Result<reqwest::Response, NodeXError> {
        let url = self.base_url.join(path);
        let payload = json!({
            "event_at": event_at.to_rfc3339(),
            "is_healthy": is_active,
        });
        let payload = DIDCommEncryptedService::generate(project_did, &payload, None)
            .await?
            .to_string();

        self.post(url.unwrap().as_ref(), &payload).await
    }

    pub async fn network(
        &self,
        path: &str,
        project_did: &str,
    ) -> Result<reqwest::Response, NodeXError> {
        let payload =
            match DIDCommEncryptedService::generate(project_did, &serde_json::Value::Null, None)
                .await
            {
                Ok(v) => v,
                Err(e) => {
                    log::error!("{:?}", e);
                    return Err(NodeXError {});
                }
            };
        let payload = match serde_json::to_string(&payload) {
            Ok(v) => v,
            Err(e) => {
                log::error!("{:?}", e);
                return Err(NodeXError {});
            }
        };
        self.post(path, &payload).await
    }

    #[allow(dead_code)]
    pub async fn put(&self, _path: &str) -> Result<reqwest::Response, NodeXError> {
        let url = self.base_url.join(_path);
        let headers = self.auth_headers("".to_string());
        if let Err(e) = headers {
            log::error!("{:?}", e);
            return Err(NodeXError {});
        }
        match self
            .instance
            .put(&url.unwrap().to_string())
            .headers(headers.unwrap())
            .send()
            .await
        {
            Ok(v) => Ok(v),
            Err(e) => {
                log::error!("{:?}", e);
                Err(NodeXError {})
            }
        }
    }

    #[allow(dead_code)]
    pub async fn delete(&self, _path: &str) -> Result<reqwest::Response, NodeXError> {
        let url = self.base_url.join(_path);
        let headers = self.auth_headers("".to_string());
        if let Err(e) = headers {
            log::error!("{:?}", e);
            return Err(NodeXError {});
        }
        match self
            .instance
            .delete(&url.unwrap().to_string())
            .headers(headers.unwrap())
            .send()
            .await
        {
            Ok(v) => Ok(v),
            Err(e) => {
                log::error!("{:?}", e);
                Err(NodeXError {})
            }
        }
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use serde::Deserialize;

    #[derive(Deserialize)]
    struct Res {
        origin: String,
    }

    #[actix_rt::test]
    #[ignore]
    async fn it_should_success_get() {
        let client_config: HubClientConfig = HubClientConfig {
            base_url: "https://httpbin.org".to_string(),
            proxy: "".to_string(),
        };

        let client = match HubClient::new(&client_config) {
            Ok(v) => v,
            Err(_) => panic!(),
        };

        let res = match client.get("/get").await {
            Ok(v) => v,
            Err(_) => panic!(),
        };

        let json: Res = match res.json().await {
            Ok(v) => v,
            Err(_) => panic!(),
        };

        assert!(!json.origin.is_empty());
    }

    #[actix_rt::test]
    #[ignore]
    async fn it_should_success_post() {
        let client_config: HubClientConfig = HubClientConfig {
            base_url: "https://httpbin.org".to_string(),
            proxy: "".to_string(),
        };

        let client = match HubClient::new(&client_config) {
            Ok(v) => v,
            Err(_) => panic!(),
        };

        let res = match client.post("/post", r#"{"key":"value"}"#).await {
            Ok(v) => v,
            Err(_) => panic!(),
        };

        let json: Res = match res.json().await {
            Ok(v) => v,
            Err(_) => panic!(),
        };

        assert!(!json.origin.is_empty());
    }

    #[actix_rt::test]
    #[ignore]
    async fn it_should_success_put() {
        let client_config: HubClientConfig = HubClientConfig {
            base_url: "https://httpbin.org".to_string(),
            proxy: "".to_string(),
        };

        let client = match HubClient::new(&client_config) {
            Ok(v) => v,
            Err(_) => panic!(),
        };

        let res = match client.put("/put").await {
            Ok(v) => v,
            Err(_) => panic!(),
        };

        let json: Res = match res.json().await {
            Ok(v) => v,
            Err(_) => panic!(),
        };

        assert!(!json.origin.is_empty());
    }

    #[actix_rt::test]
    #[ignore]
    async fn it_should_success_delete() {
        let client_config: HubClientConfig = HubClientConfig {
            base_url: "https://httpbin.org".to_string(),
            proxy: "".to_string(),
        };

        let client = match HubClient::new(&client_config) {
            Ok(v) => v,
            Err(_) => panic!(),
        };

        let res = match client.delete("/delete").await {
            Ok(v) => v,
            Err(_) => panic!(),
        };

        let json: Res = match res.json().await {
            Ok(v) => v,
            Err(_) => panic!(),
        };

        assert!(!json.origin.is_empty());
    }
}
