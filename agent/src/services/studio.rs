use crate::nodex::utils::did_accessor::{DidAccessor, DidAccessorImpl};
use crate::nodex::utils::sidetree_client::SideTreeClient;
use crate::repository::attribute_repository::{AttributeStoreRepository, AttributeStoreRequest};
use crate::repository::custom_metric_repository::CustomMetricStoreRepository;
use crate::repository::event_repository::{EventStoreRepository, EventStoreRequest};
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
use protocol::cbor::types::CustomMetric;
use protocol::did::did_repository::DidRepositoryImpl;
use protocol::didcomm::encrypted::DidCommEncryptedService;
use protocol::keyring::keypair::KeyPair;
use protocol::verifiable_credentials::did_vc::DidVcService;
use protocol::verifiable_credentials::types::VerifiableCredentials;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::VecDeque;

// The maximum JSON body size is actually 1MB
// We reserve 100KB as a buffer for Verifiable Credential capacity
const JSON_BODY_MAX_SIZE: usize = 900_000;

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
    did_repository: DidRepositoryImpl<SideTreeClient>,
    did_accessor: DidAccessorImpl,
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
        let did_accessor = DidAccessorImpl {};

        Studio {
            http_client: client,
            did_repository,
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
        let res = self
            .http_client
            .post_with_auth_header("/v1/device", payload)
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

    #[inline]
    async fn relay_to_studio_via_cbor<T: serde::Serialize + std::fmt::Debug + PartialEq>(
        &self,
        path: &str,
        request: T,
    ) -> anyhow::Result<()> {
        let my_did = self.did_accessor.get_my_did();
        let my_keyring = self.did_accessor.get_my_keyring();
        let signing_key = &my_keyring.sign_metrics.get_secret_key();
        let token = protocol::cbor::signature::Token::new(my_did);
        let request = protocol::cbor::signature::WithTokenImpl { inner: request, token };
        let payload = protocol::cbor::signature::sign_message(signing_key, &request)?;
        let res = self.http_client.post(path, payload).await?;
        let status = res.status();
        let json: Value = res.json().await.context("Failed to read response body")?;
        let message = json
            .get("message")
            .map(|v| v.to_string())
            .unwrap_or_default();
        match status {
            reqwest::StatusCode::OK => Ok(()),
            reqwest::StatusCode::NOT_FOUND => anyhow::bail!("StatusCode=404, {}", message),
            reqwest::StatusCode::INTERNAL_SERVER_ERROR => {
                anyhow::bail!("StatusCode=500, {}", message)
            }
            other => anyhow::bail!("StatusCode={other}, {}", message),
        }
    }

    #[inline]
    async fn relay_to_studio<T: serde::Serialize>(
        &self,
        path: &str,
        request: T,
    ) -> anyhow::Result<()> {
        let my_did = self.did_accessor.get_my_did();
        let my_keyring = self.did_accessor.get_my_keyring();
        let model =
            VerifiableCredentials::new(my_did, serde_json::to_value(request)?, chrono::Utc::now());
        let payload = DidVcService::generate(&self.did_repository, model, &my_keyring)
            .context("failed to generate payload")?;
        let payload = serde_json::to_string(&payload).context("failed to serialize")?;
        let res = self.http_client.post(path, payload).await?;
        let status = res.status();
        let json: Value = res.json().await.context("Failed to read response body")?;
        let message = json
            .get("message")
            .map(|v| v.to_string())
            .unwrap_or_default();
        match status {
            reqwest::StatusCode::OK => Ok(()),
            reqwest::StatusCode::NOT_FOUND => anyhow::bail!("StatusCode=404, {}", message),
            reqwest::StatusCode::INTERNAL_SERVER_ERROR => {
                anyhow::bail!("StatusCode=500, {}", message)
            }
            other => anyhow::bail!("StatusCode={other}, {}", message),
        }
    }
}

impl MessageActivityRepository for Studio {
    type Error = MessageActivityHttpError;
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

        let model = VerifiableCredentials::new(my_did, json!(request), request.occurred_at);
        let payload = DidCommEncryptedService::generate(
            &self.did_repository,
            model,
            &my_keyring,
            &project_did,
            None,
        )
        .await
        .context("failed to generate payload")?;
        let payload = serde_json::to_string(&payload).context("failed to serialize")?;

        let res = self
            .http_client
            .post("/v1/message-activity", payload)
            .await?;

        let status = res.status();
        let json: Value = res.json().await.context("Failed to read response body")?;
        let message = json
            .get("message")
            .map(|v| v.to_string())
            .unwrap_or_default();

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
                "StatusCode={other}, unexpected response"
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

        let model = VerifiableCredentials::new(my_did, json!(request), request.verified_at);
        let payload = DidCommEncryptedService::generate(
            &self.did_repository,
            model,
            &my_keyring,
            &project_did,
            None,
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
        let message = json
            .get("message")
            .map(|v| v.to_string())
            .unwrap_or_default();

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
                "StatusCode={other}, unexpected response"
            ))),
        }
    }
}

impl MetricStoreRepository for Studio {
    async fn save(&self, request: VecDeque<MetricsWithTimestamp>) -> anyhow::Result<()> {
        let mut metrics = request;
        while !metrics.is_empty() {
            let my_did = self.did_accessor.get_my_did();
            let my_keyring = self.did_accessor.get_my_keyring();
            let mut metrics_str = Vec::new();
            let mut current_size = 0;

            while let Some(m) = metrics.pop_front() {
                let item_size = serde_json::to_string(&m)?.len();
                if item_size > JSON_BODY_MAX_SIZE {
                    anyhow::bail!("invalid item size: JSON body size too large")
                }
                if current_size + item_size > JSON_BODY_MAX_SIZE {
                    metrics.push_front(m);
                    break;
                }
                current_size += item_size;
                metrics_str.push(m);
            }

            let model = VerifiableCredentials::new(my_did, json!(metrics_str), chrono::Utc::now());
            let payload = DidVcService::generate(&self.did_repository, model, &my_keyring)
                .context("failed to generate payload")?;

            let payload = serde_json::to_string(&payload).context("failed to serialize")?;
            let res = self.http_client.post("/v1/metrics", payload).await?;

            let status = res.status();
            let json: Value = res.json().await.context("Failed to read response body")?;
            let message = json
                .get("message")
                .map(|v| v.to_string())
                .unwrap_or_default();
            match status {
                reqwest::StatusCode::OK => continue,
                reqwest::StatusCode::NOT_FOUND => anyhow::bail!("StatusCode=404, {}", message),
                reqwest::StatusCode::INTERNAL_SERVER_ERROR => {
                    anyhow::bail!("StatusCode=500, {}", message);
                }
                other => anyhow::bail!("StatusCode={other}, {}", message),
            }
        }

        Ok(())
    }
}

impl EventStoreRepository for Studio {
    async fn save(&self, request: EventStoreRequest) -> anyhow::Result<()> {
        self.relay_to_studio("/v1/events", request).await
    }
}

impl CustomMetricStoreRepository for Studio {
    async fn save(&self, request: Vec<CustomMetric>) -> anyhow::Result<()> {
        self.relay_to_studio_via_cbor("/v1/custom-metrics", request)
            .await
    }
}

impl AttributeStoreRepository for Studio {
    async fn save(&self, request: AttributeStoreRequest) -> anyhow::Result<()> {
        self.relay_to_studio("/v1/tag-values", request).await
    }
}
