use crate::network::Network;
use crate::nodex::{
    errors::NodeXError,
    utils::hub_client::{HubClient, HubClientConfig},
};
use crate::{proxy_config, server_config};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

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

pub struct Hub {
    http_client: HubClient,
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
    pub hub_endpoint: String,
    pub heartbeat: u64,
}

impl Hub {
    pub fn new() -> Self {
        let server_config = server_config();
        let proxy_config = proxy_config();
        let client_config: HubClientConfig = HubClientConfig {
            base_url: server_config.hub_http_endpoint(),
            proxy: proxy_config.proxy_endpoint(),
        };

        let client = match HubClient::new(&client_config) {
            Ok(v) => v,
            Err(e) => {
                log::error!("{:?}", e);
                panic!()
            }
        };

        Hub {
            http_client: client,
        }
    }

    pub async fn register_device(
        &self,
        device_did: String,
        project_did: String,
    ) -> Result<(), NodeXError> {
        let request = RegisterDeviceRequest {
            device_did,
            project_did,
        };
        let payload = serde_json::to_string(&request).expect("failed to serialize");
        let res = match self.http_client.post("/v1/device", &payload).await {
            Ok(v) => v,
            Err(e) => {
                log::error!("{:?}", e);
                return Err(NodeXError {});
            }
        };
        match res.status() {
            reqwest::StatusCode::OK => match res.json::<EmptyResponse>().await {
                Ok(_) => Ok(()),
                Err(e) => {
                    log::error!("{:?}", e);
                    Err(NodeXError {})
                }
            },
            reqwest::StatusCode::BAD_REQUEST => {
                log::error!("StatusCode=400, bad request");
                Err(NodeXError {})
            }
            reqwest::StatusCode::INTERNAL_SERVER_ERROR => {
                log::error!("StatusCode=500, internal server error");
                Err(NodeXError {})
            }
            other => {
                log::error!("StatusCode={other}, unexpected response");
                Err(NodeXError {})
            }
        }
    }

    pub async fn send_device_info(
        &self,
        project_did: String,
        mac_address: String,
        version: String,
        os: String,
    ) -> Result<(), NodeXError> {
        let res = match self
            .http_client
            .send_device_info("/v1/device-info", &project_did, &mac_address, &version, &os)
            .await
        {
            Ok(v) => v,
            Err(e) => {
                log::error!("{:?}", e);
                return Err(NodeXError {});
            }
        };
        match res.status() {
            reqwest::StatusCode::OK => match res.json::<EmptyResponse>().await {
                Ok(_) => Ok(()),
                Err(e) => {
                    log::error!("StatusCode=200, but parse failed. {:?}", e);
                    Err(NodeXError {})
                }
            },
            reqwest::StatusCode::BAD_REQUEST => match res.json::<ErrorResponse>().await {
                Ok(v) => {
                    log::error!("StatusCode=400, error message = {:?}", v.message);
                    Err(NodeXError {})
                }
                Err(e) => {
                    log::error!("StatusCode=400, but parse failed. {:?}", e);
                    Err(NodeXError {})
                }
            },
            other => {
                log::error!("StatusCode={other}, unexpected response");
                Err(NodeXError {})
            }
        }
    }

    pub async fn get_message(&self, project_did: &str) -> Result<Vec<MessageResponse>, NodeXError> {
        let res = match self
            .http_client
            .get_message("/v1/message/list", project_did)
            .await
        {
            Ok(v) => v,
            Err(e) => {
                log::error!("{:?}", e);
                return Err(NodeXError {});
            }
        };

        match res.status() {
            reqwest::StatusCode::OK => match res.json::<Vec<MessageResponse>>().await {
                Ok(v) => Ok(v),
                Err(e) => {
                    log::error!("StatusCode=200, but parse failed. {:?}", e);
                    Err(NodeXError {})
                }
            },
            reqwest::StatusCode::BAD_REQUEST => match res.json::<ErrorResponse>().await {
                Ok(v) => {
                    log::error!("StatusCode=400, error message = {:?}", v.message);
                    Err(NodeXError {})
                }
                Err(e) => {
                    log::error!("StatusCode=400, but parse failed. {:?}", e);
                    Err(NodeXError {})
                }
            },
            other => {
                log::error!("StatusCode={other}, unexpected response");
                Err(NodeXError {})
            }
        }
    }

    pub async fn ack_message(
        &self,
        project_did: &str,
        message_id: String,
        is_verified: bool,
    ) -> Result<(), NodeXError> {
        let res = match self
            .http_client
            .ack_message("/v1/message/ack", project_did, message_id, is_verified)
            .await
        {
            Ok(v) => v,
            Err(e) => {
                log::error!("{:?}", e);
                return Err(NodeXError {});
            }
        };

        match res.json::<EmptyResponse>().await {
            Ok(_) => Ok(()),
            Err(e) => {
                log::error!("{:?}", e);
                Err(NodeXError {})
            }
        }
    }

    pub async fn send_message(
        &self,
        to_did: &str,
        message: serde_json::Value,
    ) -> Result<(), NodeXError> {
        let res = match self
            .http_client
            .send_message("/v1/message", to_did, message)
            .await
        {
            Ok(v) => v,
            Err(e) => {
                log::error!("{:?}", e);
                return Err(NodeXError {});
            }
        };
        let status = res.status();
        match status {
            reqwest::StatusCode::OK => Ok(()),
            _ => match res.json::<ErrorResponse>().await {
                Ok(v) => {
                    log::error!(
                        "StatusCode={:?}, error message = {:?}",
                        status.as_str(),
                        v.message
                    );
                    Err(NodeXError {})
                }
                Err(e) => {
                    log::error!(
                        "StatusCode={:?}, but parse failed. {:?}",
                        status.as_str(),
                        e
                    );
                    Err(NodeXError {})
                }
            },
        }
    }

    pub async fn heartbeat(
        &self,
        project_did: &str,
        is_active: bool,
        event_at: DateTime<Utc>,
    ) -> Result<(), NodeXError> {
        let res = match self
            .http_client
            .heartbeat("/v1/heartbeat", project_did, is_active, event_at)
            .await
        {
            Ok(v) => v,
            Err(e) => {
                log::error!("{:?}", e);
                return Err(NodeXError {});
            }
        };

        match res.status() {
            reqwest::StatusCode::OK => match res.json::<EmptyResponse>().await {
                Ok(_) => Ok(()),
                Err(e) => {
                    log::error!("StatusCode=200, but parse failed. {:?}", e);
                    Err(NodeXError {})
                }
            },
            reqwest::StatusCode::BAD_REQUEST => match res.json::<ErrorResponse>().await {
                Ok(v) => {
                    log::error!("StatusCode=400, error message = {:?}", v.message);
                    Err(NodeXError {})
                }
                Err(e) => {
                    log::error!("StatusCode=400, but parse failed. {:?}", e);
                    Err(NodeXError {})
                }
            },
            other => {
                log::error!("StatusCode={other}, unexpected response");
                Err(NodeXError {})
            }
        }
    }

    pub async fn network(&self) -> Result<(), NodeXError> {
        let network = Network::new();
        let project_did = network.root.project_did.expect("project_did is not set");
        let res = match self.http_client.network("/v1/network", &project_did).await {
            Ok(v) => v,
            Err(e) => {
                log::error!("{:?}", e);
                return Err(NodeXError {});
            }
        };

        match res.status() {
            reqwest::StatusCode::OK => match res.json::<NetworkResponse>().await {
                Ok(v) => {
                    let mut network_config = Network::new();
                    network_config.root.secret_key = Some(v.secret_key);
                    network_config.root.project_did = Some(v.project_did);
                    network_config.root.recipient_dids = Some(v.recipient_dids);
                    network_config.root.hub_endpoint = Some(v.hub_endpoint);
                    network_config.root.heartbeat = Some(v.heartbeat);
                    match network_config.save() {
                        Ok(_) => Ok(()),
                        Err(e) => {
                            log::error!("{:?}", e);
                            Err(NodeXError {})
                        }
                    }
                }

                Err(e) => {
                    log::error!("StatusCode=200, but parse failed. {:?}", e);
                    Err(NodeXError {})
                }
            },
            reqwest::StatusCode::BAD_REQUEST => match res.json::<ErrorResponse>().await {
                Ok(v) => {
                    log::error!("StatusCode=400, error message = {:?}", v.message);
                    Err(NodeXError {})
                }
                Err(e) => {
                    log::error!("StatusCode=400, but parse failed. {:?}", e);
                    Err(NodeXError {})
                }
            },
            other => {
                log::error!("StatusCode={other}, unexpected response");
                Err(NodeXError {})
            }
        }
    }
}
