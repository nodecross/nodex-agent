use crate::server_config;
use crate::{
    nodex::{
        keyring,
        sidetree::payload::{
            CommitmentKeys, DIDCreateRequest, DIDResolutionResponse, OperationPayloadBuilder,
        },
        utils::http_client::{HttpClient, HttpClientConfig},
    },
    repository::did_repository::DidRepository,
};

use anyhow;
use bytes::Bytes;
use reqwest::StatusCode;
use serde::Deserialize;
use std::{
    fs,
    io::Cursor,
    path::{Path, PathBuf},
    process::Command,
};
use thiserror::Error;
use zip::ZipArchive;

#[cfg(unix)]
use daemonize::Daemonize;

pub struct NodeX {
    http_client: HttpClient,
}

#[derive(Debug, Deserialize)]
pub struct SideTreeErrorBody {
    pub code: String,
    pub message: String,
}

#[derive(Debug, Error)]
#[error("SideTreeError: {status_code}")]
pub struct SideTreeError {
    pub status_code: StatusCode,
    pub error: SideTreeErrorBody,
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
    pub async fn create_identifier(&self) -> anyhow::Result<DIDResolutionResponse> {
        // NOTE: find did
        if let Ok(v) = keyring::keypair::KeyPairing::load_keyring() {
            if let Ok(did) = v.get_identifier() {
                if let Some(json) = self.find_identifier(&did).await? {
                    return Ok(json);
                }
            }
        }

        // NOTE: does not exists did key ring
        let mut keyring = keyring::keypair::KeyPairing::create_keyring()?;

        // NOTE: create payload
        let public = keyring
            .get_sign_key_pair()
            .to_public_key("signingKey", &["auth", "general"])?;
        let update = keyring.get_recovery_key_pair().to_jwk(false)?;
        let recovery = keyring.get_update_key_pair().to_jwk(false)?;
        let payload = OperationPayloadBuilder::did_create_payload(&DIDCreateRequest {
            public_keys: vec![public],
            commitment_keys: CommitmentKeys { recovery, update },
            service_endpoints: vec![],
        })?;

        let res = self
            .http_client
            .post("/api/v1/operations", &payload)
            .await?;

        if res.status().is_success() {
            let json = res.json::<DIDResolutionResponse>().await?;

            // NOTE: save context
            keyring.save(&json.did_document.id);

            Ok(json)
        } else {
            let status = res.status();
            let error = res.json::<SideTreeErrorBody>().await?;
            Err(SideTreeError {
                status_code: status,
                error,
            }
            .into())
        }
    }

    // NOTE: DONE
    pub async fn find_identifier(
        &self,
        did: &str,
    ) -> anyhow::Result<Option<DIDResolutionResponse>> {
        let res = self
            .http_client
            .get(&(format!("/api/v1/identifiers/{}", &did)))
            .await?;

        match res.status() {
            StatusCode::OK => Ok(Some(res.json::<DIDResolutionResponse>().await?)),
            StatusCode::NOT_FOUND => Ok(None),
            other => {
                let error = res.json::<SideTreeErrorBody>().await?;
                Err(SideTreeError {
                    status_code: other,
                    error,
                }
                .into())
            }
        }
    }

    pub async fn update_version(
        &self,
        binary_url: &str,
        output_path: PathBuf,
    ) -> anyhow::Result<()> {
        anyhow::ensure!(
            binary_url.starts_with("https://github.com/nodecross/nodex/releases/download/"),
            "Invalid url"
        );

        #[cfg(unix)]
        let agent_filename = { "nodex-agent" };
        #[cfg(windows)]
        let agent_filename = { "nodex-agent.exe" };

        let agent_path = output_path.join(agent_filename);

        let response = reqwest::get(binary_url).await?;
        let content = response.bytes().await?;

        if PathBuf::from(&agent_path).exists() {
            fs::remove_file(&agent_path)?;
        }
        self.extract_zip(content, &output_path)?;

        self.run_agent(&agent_path)?;

        Ok(())
    }

    fn extract_zip(&self, archive_data: Bytes, output_path: &Path) -> anyhow::Result<()> {
        let cursor = Cursor::new(archive_data);
        let mut archive = ZipArchive::new(cursor)?;

        for i in 0..archive.len() {
            let mut file = archive.by_index(i)?;
            let file_path = output_path.join(file.mangled_name());

            if file.is_file() {
                if let Some(parent) = file_path.parent() {
                    std::fs::create_dir_all(parent)?;
                }
                let mut output_file = fs::File::create(&file_path)?;
                std::io::copy(&mut file, &mut output_file)?;
            } else if file.is_dir() {
                std::fs::create_dir_all(&file_path)?;
            }
        }

        Ok(())
    }

    #[cfg(unix)]
    fn run_agent(&self, agent_path: &Path) -> anyhow::Result<()> {
        Command::new("chmod").arg("+x").arg(agent_path).status()?;

        let daemonize = Daemonize::new();
        daemonize.start().expect("Failed to update nodex process");
        std::process::Command::new(agent_path)
            .spawn()
            .expect("Failed to execute command");
        Ok(())
    }

    #[cfg(windows)]
    fn run_agent(&self, agent_path: &Path) -> anyhow::Result<()> {
        let agent_path_str = agent_path
            .to_str()
            .ok_or_else(|| anyhow::anyhow!("Failed to convert agent_path to string"))?;

        let status = Command::new("cmd")
            .args(&["/C", "start", agent_path_str])
            .status()?;

        if !status.success() {
            eprintln!("Command execution failed with status: {}", status);
        } else {
            println!("Started child process");
        }

        Ok(())
    }
}

// TODO: use other impl
#[async_trait::async_trait]
impl DidRepository for NodeX {
    async fn create_identifier(&self) -> anyhow::Result<DIDResolutionResponse> {
        NodeX::create_identifier(self).await
    }

    async fn find_identifier(&self, did: &str) -> anyhow::Result<Option<DIDResolutionResponse>> {
        NodeX::find_identifier(self, did).await
    }
}
