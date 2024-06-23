use crate::nodex::utils::did_accessor::{DIDAccessor, DIDAccessorImpl};
use crate::nodex::utils::sidetree_client::SideTreeClient;
use crate::repository::message_activity_repository::MessageActivityHttpError;
use crate::repository::metric_repository::{MetricStoreRepository, MetricsWithTimestamp};
use crate::server_config;
use crate::{
    nodex::utils::studio_client::{StudioClient, StudioClientConfig},
    repository::message_activity_repository::{
        CreatedMessageActivityRequest, MessageActivityRepository, VerifiedMessageActivityRequest,
    },
};
use anyhow::Context;
use nodex_didcomm::did::did_repository::DidRepositoryImpl;
use nodex_didcomm::didcomm::encrypted::DIDCommEncryptedService;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

#[derive(Deserialize)]
pub struct EmptyResponse {}

#[derive(Deserialize, Debug, Clone)]
pub struct MessageResponse {
    pub id: String,
    pub raw_message: String,
}

#[derive(Deserialize, Debug, Clone)]
struct ErrorResponse {
    pub message: String,
}

pub struct Studio {
    http_client: StudioClient,
    didcomm_service: DIDCommEncryptedService<DidRepositoryImpl<SideTreeClient>>,
    did_accessor: DIDAccessorImpl,
}

#[derive(Debug, Serialize, Deserialize)]
struct RegisterDeviceRequest {
    device_did: String,
    project_did: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct SendDeviceInfoRequest {
    device_did: String,
    mac_address: String,
    version: String,
    os: String,
}

#[derive(Deserialize, Debug, Clone)]
pub struct NetworkResponse {
    pub secret_key: String,
    pub project_did: String,
    pub recipient_dids: Vec<String>,
    pub studio_endpoint: String,
    pub heartbeat: u64,
}

impl Studio {
    pub fn new() -> Self {
        let server_config = server_config();
        let client_config: StudioClientConfig = StudioClientConfig {
            base_url: server_config.studio_http_endpoint(),
        };

        let client = match StudioClient::new(&client_config) {
            Ok(v) => v,
            Err(e) => {
                log::error!("{:?}", e);
                panic!()
            }
        };

        let sidetree_client = SideTreeClient::new(&server_config.did_http_endpoint())
            .expect("failed to create sidetree client");
        let did_repository = DidRepositoryImpl::new(sidetree_client);
        let didcomm_service =
            DIDCommEncryptedService::new(did_repository, Some(server_config.did_attachment_link()));
        let did_accessor = DIDAccessorImpl {};

        Studio {
            http_client: client,
            didcomm_service,
            did_accessor,
        }
    }

    pub async fn register_device(
        &self,
        device_did: String,
        project_did: String,
    ) -> anyhow::Result<()> {
        let request = RegisterDeviceRequest {
            device_did,
            project_did,
        };
        let payload = serde_json::to_string(&request).expect("failed to serialize");
        let res = self.http_client.post("/v1/device", &payload).await?;

        let status = res.status();

        let json: Value = res.json().await.context("Failed to read response body")?;
        let message = json
            .get("message")
            .map(|v| v.to_string())
            .unwrap_or_default();

        match status {
            reqwest::StatusCode::OK => Ok(()),
            reqwest::StatusCode::BAD_REQUEST => {
                anyhow::bail!("StatusCode=400, {}", message)
            }
            reqwest::StatusCode::UNAUTHORIZED => {
                anyhow::bail!("StatusCode=401, {}", message)
            }
            reqwest::StatusCode::NOT_FOUND => {
                anyhow::bail!("StatusCode=404, {}", message)
            }
            reqwest::StatusCode::INTERNAL_SERVER_ERROR => {
                anyhow::bail!("StatusCode=500, {}", message);
            }
            other => {
                anyhow::bail!("StatusCode={other}, {}", message);
            }
        }
    }

    pub async fn send_device_info(
        &self,
        project_did: String,
        mac_address: String,
        version: String,
        os: String,
    ) -> anyhow::Result<()> {
        let res = self
            .http_client
            .send_device_info("/v1/device-info", &project_did, &mac_address, &version, &os)
            .await?;

        let status = res.status();

        let json: Value = res.json().await.context("Failed to read response body")?;
        let message = json
            .get("message")
            .map(|v| v.to_string())
            .unwrap_or_default();

        match status {
            reqwest::StatusCode::OK => Ok(()),
            reqwest::StatusCode::BAD_REQUEST => {
                anyhow::bail!("StatusCode=400, {}", message)
            }
            reqwest::StatusCode::NOT_FOUND => {
                anyhow::bail!("StatusCode=404, {}", message)
            }
            other => {
                anyhow::bail!("StatusCode={other}, {}", message);
            }
        }
    }

    pub async fn get_message(&self, project_did: &str) -> anyhow::Result<Vec<MessageResponse>> {
        let res = self
            .http_client
            .get_message("/v1/message/list", project_did)
            .await?;

        match res.status() {
            reqwest::StatusCode::OK => match res.json::<Vec<MessageResponse>>().await {
                Ok(v) => Ok(v),
                Err(e) => anyhow::bail!("StatusCode=200, but parse failed. {:?}", e),
            },
            reqwest::StatusCode::BAD_REQUEST => match res.json::<ErrorResponse>().await {
                Ok(v) => anyhow::bail!("StatusCode=400, error message = {:?}", v.message),
                Err(e) => anyhow::bail!("StatusCode=400, but parse failed. {:?}", e),
            },
            other => anyhow::bail!("StatusCode={other}, unexpected response"),
        }
    }

    pub async fn ack_message(
        &self,
        project_did: &str,
        message_id: String,
        is_verified: bool,
    ) -> anyhow::Result<()> {
        let res = self
            .http_client
            .ack_message("/v1/message/ack", project_did, message_id, is_verified)
            .await?;

        res.json::<EmptyResponse>().await?;
        Ok(())
    }

    pub async fn network(&self) -> anyhow::Result<()> {
        let project_did = {
            let network = crate::network_config();
            let network = network.lock();
            network.get_project_did().expect("project_did is not set")
        };

        let res = self
            .http_client
            .network("/v1/network", &project_did)
            .await?;

        match res.status() {
            reqwest::StatusCode::OK => match res.json::<NetworkResponse>().await {
                Ok(v) => {
                    let network = crate::network_config();
                    let mut network = network.lock();
                    network.save_secret_key(&v.secret_key);
                    network.save_project_did(&v.project_did);
                    network.save_recipient_dids(v.recipient_dids);
                    network.save_studio_endpoint(&v.studio_endpoint);
                    network.save_heartbeat(v.heartbeat);
                    Ok(())
                }
                Err(e) => anyhow::bail!("StatusCode=200, but parse failed. {:?}", e),
            },
            reqwest::StatusCode::BAD_REQUEST => match res.json::<ErrorResponse>().await {
                Ok(v) => anyhow::bail!("StatusCode=400, error message = {:?}", v.message),
                Err(e) => anyhow::bail!("StatusCode=400, but parse failed. {:?}", e),
            },
            other => anyhow::bail!("StatusCode={other}, unexpected response"),
        }
    }
}

#[async_trait::async_trait]
impl MessageActivityRepository for Studio {
    async fn add_create_activity(
        &self,
        request: CreatedMessageActivityRequest,
    ) -> Result<(), MessageActivityHttpError> {
        // TODO: refactoring more simple

        let project_did = {
            let network = crate::network_config();
            let network = network.lock();
            network.get_project_did().expect("project_did is not set")
        };
        let my_did = self.did_accessor.get_my_did();
        let my_keyring = self.did_accessor.get_my_keyring();

        let payload = self
            .didcomm_service
            .generate(
                &my_did,
                &project_did,
                &my_keyring,
                &json!(request),
                None,
                request.occurred_at,
            )
            .await
            .context("failed to generate payload")?;
        let payload = serde_json::to_string(&payload).context("failed to serialize")?;

        let res = self
            .http_client
            .post("/v1/message-activity", &payload)
            .await?;

        let status = res.status();
        let json: Value = res.json().await.context("Failed to read response body")?;
        let message = if let Some(message) = json.get("message").map(|v| v.to_string()) {
            message
        } else {
            "".to_string()
        };

        match status {
            reqwest::StatusCode::OK => Ok(()),
            reqwest::StatusCode::BAD_REQUEST => Err(MessageActivityHttpError::BadRequest(message)),
            reqwest::StatusCode::UNAUTHORIZED => {
                Err(MessageActivityHttpError::Unauthorized(message))
            }
            reqwest::StatusCode::FORBIDDEN => Err(MessageActivityHttpError::Forbidden(message)),
            reqwest::StatusCode::NOT_FOUND => Err(MessageActivityHttpError::NotFound(message)),
            reqwest::StatusCode::CONFLICT => Err(MessageActivityHttpError::Conflict(message)),
            reqwest::StatusCode::INTERNAL_SERVER_ERROR => {
                Err(MessageActivityHttpError::InternalServerError(message))
            }
            other => Err(MessageActivityHttpError::Other(anyhow::anyhow!(
                "StatusCode={}, unexpected response",
                other
            ))),
        }
    }

    async fn add_verify_activity(
        &self,
        request: VerifiedMessageActivityRequest,
    ) -> Result<(), MessageActivityHttpError> {
        // TODO: refactoring more simple
        let project_did = {
            let network = crate::network_config();
            let network = network.lock();
            network.get_project_did().expect("project_did is not set")
        };
        let my_did = self.did_accessor.get_my_did();
        let my_keyring = self.did_accessor.get_my_keyring();

        let payload = self
            .didcomm_service
            .generate(
                &my_did,
                &project_did,
                &my_keyring,
                &json!(request),
                None,
                request.verified_at,
            )
            .await
            .context("failed to generate payload")?;
        let payload = serde_json::to_string(&payload).context("failed to serialize")?;

        let res = self
            .http_client
            .put("/v1/message-activity", &payload)
            .await?;

        let status = res.status();
        let json: Value = res.json().await.context("Failed to read response body")?;
        let message = if let Some(message) = json.get("message").map(|v| v.to_string()) {
            message
        } else {
            "".to_string()
        };

        match status {
            reqwest::StatusCode::OK => Ok(()),
            reqwest::StatusCode::BAD_REQUEST => Err(MessageActivityHttpError::BadRequest(message)),
            reqwest::StatusCode::UNAUTHORIZED => {
                Err(MessageActivityHttpError::Unauthorized(message))
            }
            reqwest::StatusCode::FORBIDDEN => Err(MessageActivityHttpError::Forbidden(message)),
            reqwest::StatusCode::NOT_FOUND => Err(MessageActivityHttpError::NotFound(message)),
            reqwest::StatusCode::CONFLICT => Err(MessageActivityHttpError::Conflict(message)),
            reqwest::StatusCode::INTERNAL_SERVER_ERROR => {
                Err(MessageActivityHttpError::InternalServerError(message))
            }
            other => Err(MessageActivityHttpError::Other(anyhow::anyhow!(
                "StatusCode={}, unexpected response",
                other
            ))),
        }
    }
}

#[derive(Serialize)]
struct MetricStr {
    metric_type: String,
    value: f32,
}

#[derive(Serialize)]
struct MetricsWithTimestampStr {
    timestamp: chrono::DateTime<chrono::Utc>,
    metrics: Vec<MetricStr>,
}

#[async_trait::async_trait]
impl MetricStoreRepository for Studio {
    async fn save(&self, request: Vec<MetricsWithTimestamp>) -> anyhow::Result<()> {
        let metrics_str = request
            .into_iter()
            .map(|m| MetricsWithTimestampStr {
                timestamp: m.timestamp,
                metrics: m
                    .metrics
                    .into_iter()
                    .map(|metric| MetricStr {
                        metric_type: metric.metric_type.to_string(),
                        value: metric.value,
                    })
                    .collect::<Vec<MetricStr>>(),
            })
            .collect::<Vec<MetricsWithTimestampStr>>();

        let project_did = {
            let network = crate::network_config();
            let network = network.lock();
            network.get_project_did().expect("project_did is not set")
        };
        let my_did = self.did_accessor.get_my_did();
        let my_keyring = self.did_accessor.get_my_keyring();
        let payload = self
            .didcomm_service
            .generate(
                &my_did,
                &project_did,
                &my_keyring,
                &json!(metrics_str),
                None,
                chrono::Utc::now(),
            )
            .await
            .context("failed to generate payload")?;

        let payload = serde_json::to_string(&payload).context("failed to serialize")?;
        let res = self.http_client.post("/v1/metrics", &payload).await?;

        let status = res.status();
        let json: Value = res.json().await.context("Failed to read response body")?;
        let message = if let Some(message) = json.get("message").map(|v| v.to_string()) {
            message
        } else {
            "".to_string()
        };
        match status {
            reqwest::StatusCode::OK => Ok(()),
            reqwest::StatusCode::NOT_FOUND => anyhow::bail!("StatusCode=404, {}", message),
            reqwest::StatusCode::INTERNAL_SERVER_ERROR => {
                anyhow::bail!("StatusCode=500, {}", message);
            }
            other => anyhow::bail!("StatusCode={other}, {}", message),
        }
    }
}
