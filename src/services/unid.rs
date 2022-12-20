use std::time::Duration;

use crate::{unid::{errors::UNiDError, keyring, sidetree::payload::{OperationPayload, DIDCreateRequest, CommitmentKeys, DIDCreateResponse, DIDResolutionResponse}, utils::http_client::{HttpClient, HttpClientConfig}}, config::KeyPair};
use rumqttc::{MqttOptions, AsyncClient, QoS};
use serde_json::Value;
use cuid;

pub struct UNiD {
    http_client: HttpClient
}

impl UNiD {
    pub fn new() -> Self {
        let client_config: HttpClientConfig = HttpClientConfig {
            base_url: "https://did.getunid.io".to_string(),
        };

        let client = match HttpClient::new(&client_config) {
            Ok(v) => v,
            Err(_) => panic!()
        };

        UNiD { http_client: client }
    }

    // NOTE: DONE
    pub async fn create_identifier(&self) -> Result<DIDCreateResponse, UNiDError> {
        let mut keyring = match keyring::mnemonic::MnemonicKeyring::create_keyring() {
            Ok(v) => v,
            Err(_) => return Err(UNiDError{}),
        };

        // NOTE: create payload
        let public = match keyring.get_sign_key_pair().to_public_key("signingKey", &vec!["auth", "general"]) {
            Ok(v) => v,
            Err(_) => return Err(UNiDError{}),
        };
        let update = match keyring.get_recovery_key_pair().to_jwk(false) {
            Ok(v) => v,
            Err(_) => return Err(UNiDError{}),
        };
        let recovery = match keyring.get_update_key_pair().to_jwk(false) {
            Ok(v) => v,
            Err(_) => return Err(UNiDError{}),
        };

        let payload = match OperationPayload::did_create_payload(&DIDCreateRequest {
            public_keys: vec![ public ],
            commitment_keys: CommitmentKeys {
                recovery,
                update,
            },
            service_endpoints: vec![],
        }) {
            Ok(v) => v,
            Err(_) => return Err(UNiDError{}),
        };

        let res = match self.http_client.post(&("/api/v1/operations"), &payload).await {
            Ok(v) => v,
            Err(_) => return Err(UNiDError{}),
        };

        let json = match res.json::<DIDCreateResponse>().await {
            Ok(v) => v,
            Err(_) => return Err(UNiDError{}),
        };

        // NOTE: save context
        keyring.save(&json.did_document.id);

        Ok(json)
    }

    // NOTE: DONE
    pub async fn find_identifier(&self, did: &str) -> Result<DIDResolutionResponse, UNiDError> {
        let res = match self.http_client.get(&(format!("/api/v1/identifiers/{}", &did))).await {
            Ok(v) => v,
            Err(_) => return Err(UNiDError{})
        };

        match res.json::<DIDResolutionResponse>().await {
            Ok(v) => Ok(v),
            Err(_) => Err(UNiDError{})
        }
    }

    pub async fn transfer(&self, other_did: &str, message: &Value) -> Result<Value, UNiDError> {
        let internal = crate::services::internal::Internal::new();

        let demo_host = "demo-mqtt.getunid.io".to_string();
        let demo_port = 1883;
        let demo_topic = "unid/demo".to_string();

        // NOTE: didcomm (enc)
        let container = match internal.didcomm_generate_encrypted_message(&other_did, &message).await {
            Ok(v) => v,
            Err(_) => return Err(UNiDError{}),
        };

        // NOTE: send message over mqtt
        let id = match cuid::cuid() {
            Ok(v) => v,
            Err(_) => return Err(UNiDError{}),
        };

        let mut mqttoptions = MqttOptions::new(&id, demo_host, demo_port);
        mqttoptions.set_clean_session(true);
        mqttoptions.set_keep_alive(Duration::from_secs(5));

        let (mut client, mut eventloop) = AsyncClient::new(mqttoptions, 10);

        match client.publish(demo_topic, QoS::AtLeastOnce, false, container.to_string().as_bytes()).await {
            Ok(_) => {},
            Err(_) => return Err(UNiDError{}),
        };

        let mut count = 0;

        while let Ok(notification) = eventloop.poll().await {
            println!("{:?}", notification);

            count = count + 1;

            if count > 1 {
                break
            }
        }

        match client.disconnect().await {
            Ok(_) => {},
            Err(_) => panic!(),
        };

        Ok(container)
    }
}