use crate::services::hub::Hub;
use crate::services::nodex::NodeX;
use anyhow::anyhow;
use nodex_didcomm::didcomm::encrypted::DIDCommEncryptedService;
use nodex_didcomm::keyring::keypair::KeyPairing;
use serde::{Deserialize, Serialize};
use std::{sync::Arc, time::Duration};
use tokio::sync::Notify;

#[derive(Deserialize)]
enum OperationType {
    UpdateAgent,
    UpdateNetworkJson,
}

#[derive(Deserialize, Serialize, Debug, Clone)]
struct AckMessage {
    pub message_id: String,
}

struct MessageReceiveUsecase {
    hub: Hub,
    agent: NodeX,
    project_did: String,
}

impl MessageReceiveUsecase {
    pub fn new() -> Self {
        let network = crate::network_config();
        let network = network.lock();
        let project_did = if let Some(v) = network.get_project_did() {
            v
        } else {
            panic!("Failed to read project_did")
        };
        drop(network);

        Self {
            hub: Hub::new(),
            agent: NodeX::new(),
            project_did,
        }
    }

    pub async fn receive_message(&self) -> anyhow::Result<()> {
        fn get_my_keyring() -> KeyPairing {
            let config = crate::app_config();
            let config = config.lock();
            config.load_keyring().expect("failed to load keyring")
        }

        // TODO: refactoring more simple
        let service = DIDCommEncryptedService::new(NodeX::new(), None);

        for m in self.hub.get_message(&self.project_did).await? {
            let my_keyring = get_my_keyring();
            let json_message = serde_json::from_str(&m.raw_message)
                .map_err(|e| anyhow::anyhow!("Invalid Json: {:?}", e))?;
            log::info!("Receive message. message_id = {:?}", m.id);
            match service.verify(&my_keyring, &json_message).await {
                Ok(verified) => {
                    log::info!(
                        "Verify success. message_id = {}, from = {}",
                        m.id,
                        verified.message.issuer.id
                    );
                    if verified.message.issuer.id == self.project_did {
                        let container = verified.message.credential_subject.container;
                        let operation_type = container["operation"].clone();
                        match serde_json::from_value::<OperationType>(operation_type) {
                            Ok(OperationType::UpdateAgent) => {
                                let binary_url = container["binary_url"]
                                    .as_str()
                                    .ok_or(anyhow!("the container does n't have binary_url"))?;
                                self.agent
                                    .update_version(binary_url, "/tmp/nodex-agent")
                                    .await?;
                                self.hub.ack_message(&self.project_did, m.id, true).await?;
                            }
                            Ok(OperationType::UpdateNetworkJson) => {
                                self.hub.network().await?;
                                self.hub.ack_message(&self.project_did, m.id, true).await?;
                            }
                            Err(e) => {
                                log::error!("Json Parse Error: {:?}", e);
                            }
                        }
                        continue;
                    } else {
                        log::error!("Not supported");
                    }
                }
                Err(_) => {
                    log::error!("Verify failed : message_id = {}", m.id);
                    self.hub.ack_message(&self.project_did, m.id, false).await?;
                    continue;
                }
            }
        }

        Ok(())
    }
}

pub async fn polling_task(shutdown_notify: Arc<Notify>) {
    log::info!("Polling task is started");

    let usecase = MessageReceiveUsecase::new();

    let mut interval = tokio::time::interval(Duration::from_secs(3600));
    loop {
        tokio::select! {
            _ = interval.tick() => {
                match usecase.receive_message().await {
                    Ok(_) => {},
                    Err(e) => log::error!("Error: {:?}", e),
                }
            }
            _ = shutdown_notify.notified() => {
                break;
            },
        }
    }

    log::info!("Polling task is stopped");
}
