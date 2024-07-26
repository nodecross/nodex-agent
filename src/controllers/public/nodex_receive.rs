use crate::nodex::utils::did_accessor::{DIDAccessorImpl, DidAccessor};
use crate::services::nodex::NodeX;
use crate::services::studio::{MessageResponse, Studio};
use anyhow::anyhow;
use nodex_didcomm::didcomm::encrypted::DIDCommEncryptedService;

use serde::{Deserialize, Serialize};
use serde_json;
use std::{path::PathBuf, sync::Arc, time::Duration};
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
    studio: Studio,
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
            studio: Studio::new(),
            agent: NodeX::new(),
            project_did,
        }
    }

    async fn handle_invalid_json(
        &self,
        m: &MessageResponse,
        e: serde_json::Error,
    ) -> Result<(), anyhow::Error> {
        self.studio
            .ack_message(&self.project_did, m.id.clone(), false)
            .await?;
        Err(anyhow::anyhow!("Invalid Json: {:?}", e))
    }

    pub async fn receive_message(&self) -> anyhow::Result<()> {
        // TODO: refactoring more simple
        let service = DIDCommEncryptedService::new(NodeX::new(), None);

        for m in self.studio.get_message(&self.project_did).await? {
            let json_message = match serde_json::from_str(&m.raw_message) {
                Ok(msg) => msg,
                Err(e) => return self.handle_invalid_json(&m, e).await,
            };
            log::info!("Receive message. message_id = {:?}", m.id);
            match service
                .verify(&DIDAccessorImpl {}.get_my_keyring(), &json_message)
                .await
            {
                Ok(verified) => {
                    log::info!(
                        "Verify success. message_id = {}, from = {}",
                        m.id,
                        verified.message.issuer.id
                    );
                    self.studio
                        .ack_message(&self.project_did, m.id, true)
                        .await?;
                    if verified.message.issuer.id == self.project_did {
                        let container = verified.message.credential_subject.container;
                        let operation_type = container["operation"].clone();
                        match serde_json::from_value::<OperationType>(operation_type) {
                            Ok(OperationType::UpdateAgent) => {
                                let binary_url = container["binary_url"]
                                    .as_str()
                                    .ok_or(anyhow!("the container does n't have binary_url"))?;

                                #[cfg(unix)]
                                let output_path = { PathBuf::from("/tmp/nodex-agent") };
                                #[cfg(windows)]
                                let output_path = { PathBuf::from("C:\\Temp\\nodex-agent") };

                                self.agent.update_version(binary_url, output_path).await?;
                            }
                            Ok(OperationType::UpdateNetworkJson) => {
                                self.studio.network().await?;
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
                    self.studio
                        .ack_message(&self.project_did, m.id, false)
                        .await?;
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
