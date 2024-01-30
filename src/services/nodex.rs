use super::internal::didcomm_encrypted::DIDCommEncryptedService;
use crate::nodex::{
    errors::NodeXError,
    keyring,
    sidetree::payload::{
        CommitmentKeys, DIDCreateRequest, DIDResolutionResponse, OperationPayload,
    },
    utils::http_client::{HttpClient, HttpClientConfig},
};
use crate::server_config;
use serde_json::{json, Value};
use std::{fs, process::Command};

pub struct NodeX {
    http_client: HttpClient,
}

impl NodeX {
    pub fn new() -> Self {
        let server_config = server_config();
        let client_config: HttpClientConfig = HttpClientConfig {
            base_url: server_config.did_http_endpoint(),
        };

        let client = match HttpClient::new(&client_config) {
            Ok(v) => v,
            Err(e) => {
                log::error!("{:?}", e);
                panic!()
            }
        };

        NodeX {
            http_client: client,
        }
    }

    // NOTE: DONE
    pub async fn create_identifier(&self) -> Result<DIDResolutionResponse, NodeXError> {
        // NOTE: find did
        if let Ok(v) = keyring::keypair::KeyPairing::load_keyring() {
            if let Ok(did) = v.get_identifier() {
                if let Ok(json) = self.find_identifier(&did).await {
                    return Ok(json);
                }
            }
        }

        // NOTE: does not exists did key ring
        let mut keyring = match keyring::keypair::KeyPairing::create_keyring() {
            Ok(v) => v,
            Err(e) => {
                log::error!("{:?}", e);
                return Err(NodeXError {});
            }
        };

        // NOTE: create payload
        let public = match keyring
            .get_sign_key_pair()
            .to_public_key("signingKey", &["auth", "general"])
        {
            Ok(v) => v,
            Err(e) => {
                log::error!("{:?}", e);
                return Err(NodeXError {});
            }
        };
        let update = match keyring.get_recovery_key_pair().to_jwk(false) {
            Ok(v) => v,
            Err(e) => {
                log::error!("{:?}", e);
                return Err(NodeXError {});
            }
        };
        let recovery = match keyring.get_update_key_pair().to_jwk(false) {
            Ok(v) => v,
            Err(e) => {
                log::error!("{:?}", e);
                return Err(NodeXError {});
            }
        };

        let payload = match OperationPayload::did_create_payload(&DIDCreateRequest {
            public_keys: vec![public],
            commitment_keys: CommitmentKeys { recovery, update },
            service_endpoints: vec![],
        }) {
            Ok(v) => v,
            Err(e) => {
                log::error!("{:?}", e);
                return Err(NodeXError {});
            }
        };

        let res = match self.http_client.post("/api/v1/operations", &payload).await {
            Ok(v) => v,
            Err(e) => {
                log::error!("{:?}", e);
                return Err(NodeXError {});
            }
        };

        let json = match res.json::<DIDResolutionResponse>().await {
            Ok(v) => v,
            Err(e) => {
                log::error!("{:?}", e);
                return Err(NodeXError {});
            }
        };

        // NOTE: save context
        keyring.save(&json.did_document.id);

        Ok(json)
    }

    // NOTE: DONE
    pub async fn find_identifier(&self, did: &str) -> Result<DIDResolutionResponse, NodeXError> {
        let res = match self
            .http_client
            .get(&(format!("/api/v1/identifiers/{}", &did)))
            .await
        {
            Ok(v) => v,
            Err(e) => {
                log::error!("{:?}", e);
                return Err(NodeXError {});
            }
        };

        match res.json::<DIDResolutionResponse>().await {
            Ok(v) => Ok(v),
            Err(e) => {
                log::error!("{:?}", e);
                Err(NodeXError {})
            }
        }
    }

    #[allow(dead_code)]
    pub async fn transfer(
        &self,
        to_did: &str,
        messages: &Vec<Value>,
        metadata: &Value,
    ) -> Result<Value, NodeXError> {
        // NOTE: didcomm (enc)
        let container =
            match DIDCommEncryptedService::generate(to_did, &json!(messages), Some(metadata)).await
            {
                Ok(v) => v,
                Err(e) => {
                    log::error!("{:?}", e);
                    return Err(NodeXError {});
                }
            };

        Ok(container)
    }

    pub async fn update_version(
        &self,
        binary_url: &str,
        output_path: &str,
    ) -> Result<(), NodeXError> {
        let output_path = if output_path.ends_with("/") {
            output_path.trim_end()
        } else {
            output_path
        };
        let agent_path = format!("{}/nodex-agent", output_path);

        let response = reqwest::get(binary_url).await;
        match response {
            Ok(r) => {
                let content = match r.bytes().await {
                    Ok(c) => c,
                    Err(_) => return Err(NodeXError {}),
                };
                match fs::write(format!("{}.zip", agent_path), &content) {
                    Ok(_) => (),
                    Err(_) => return Err(NodeXError {}),
                };
                match Command::new("unzip")
                    .arg("-o")
                    .arg(format!("{}.zip", agent_path))
                    .arg("-d")
                    .arg(output_path)
                    .status()
                {
                    Ok(_) => (),
                    Err(_) => return Err(NodeXError {}),
                };
                match Command::new("chmod").arg("+x").arg(&agent_path).status() {
                    Ok(_) => (),
                    Err(_) => return Err(NodeXError {}),
                };
                match Command::new(&agent_path).spawn() {
                    Ok(_) => (),
                    Err(_) => return Err(NodeXError {}),
                };
                Ok(())
            }
            Err(_) => Err(NodeXError {}),
        }
    }
}
