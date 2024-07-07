use crate::nodex::keyring;
use crate::nodex::utils::sidetree_client::SideTreeClient;
use crate::server_config;
use daemonize::Daemonize;
use nodex_didcomm::did::did_repository::{
    CreateIdentifierError, DidRepository, DidRepositoryImpl, FindIdentifierError,
};
use nodex_didcomm::did::sidetree::payload::DIDResolutionResponse;
use nodex_didcomm::keyring::keypair::KeyPairing;
use std::{fs, io::Cursor, path::PathBuf, process::Command};
use zip_extract;

pub struct NodeX {
    repository: DidRepositoryImpl<SideTreeClient>,
}

impl NodeX {
    pub fn new() -> Self {
        let server_config = server_config();
        let sidetree_client = SideTreeClient::new(&server_config.did_http_endpoint()).unwrap();
        let did_repository = DidRepositoryImpl::new(sidetree_client);

        NodeX {
            repository: did_repository,
        }
    }

    // NOTE: DONE
    pub async fn create_identifier(&self) -> anyhow::Result<DIDResolutionResponse> {
        // NOTE: find did
        if let Ok(v) = keyring::keypair::KeyPairingWithConfig::load_keyring() {
            if let Ok(did) = v.get_identifier() {
                if let Some(json) = self.find_identifier(&did).await? {
                    return Ok(json);
                }
            }
        }

        let mut keyring_with_config = keyring::keypair::KeyPairingWithConfig::create_keyring()?;
        let res = self
            .repository
            .create_identifier(keyring_with_config.get_keyring())
            .await?;
        keyring_with_config.save(&res.did_document.id);

        Ok(res)
    }

    // NOTE: DONE
    pub async fn find_identifier(
        &self,
        did: &str,
    ) -> anyhow::Result<Option<DIDResolutionResponse>> {
        let res = self.repository.find_identifier(did).await?;

        Ok(res)
    }

    pub async fn update_version(&self, binary_url: &str, output_path: &str) -> anyhow::Result<()> {
        anyhow::ensure!(
            binary_url.starts_with("https://github.com/nodecross/nodex/releases/download/"),
            "Invalid url"
        );
        let output_path = if output_path.ends_with('/') {
            output_path.trim_end()
        } else {
            output_path
        };
        let agent_path = format!("{}/nodex-agent", output_path);
        let response = reqwest::get(binary_url).await?;
        let content = response.bytes().await?;
        if PathBuf::from(&agent_path).exists() {
            fs::remove_file(&agent_path)?;
        }
        let target_dir = PathBuf::from(output_path);
        zip_extract::extract(Cursor::new(content), &target_dir, true)?;

        Command::new("chmod").arg("+x").arg(&agent_path).status()?;

        let daemonize = Daemonize::new();
        daemonize.start().expect("Failed to update nodex process");
        std::process::Command::new(&agent_path)
            .spawn()
            .expect("Failed to execute command");

        Ok(())
    }
}

// TODO: remove this. use DidRepositoryImpl directly
#[async_trait::async_trait]
impl DidRepository for NodeX {
    async fn create_identifier(
        &self,
        keyring: KeyPairing,
    ) -> Result<DIDResolutionResponse, CreateIdentifierError> {
        self.repository.create_identifier(keyring).await
    }

    async fn find_identifier(
        &self,
        did: &str,
    ) -> Result<Option<DIDResolutionResponse>, FindIdentifierError> {
        self.repository.find_identifier(did).await
    }
}
