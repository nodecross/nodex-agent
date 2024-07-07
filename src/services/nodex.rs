use crate::nodex::keyring;
use crate::nodex::utils::sidetree_client::SideTreeClient;
use crate::server_config;
use anyhow;
use bytes::Bytes;
use nodex_didcomm::did::did_repository::{
    CreateIdentifierError, DidRepository, DidRepositoryImpl, FindIdentifierError,
};
use nodex_didcomm::did::sidetree::payload::DIDResolutionResponse;
use nodex_didcomm::keyring::keypair::KeyPairing;
use std::{
    fs,
    io::Cursor,
    path::{Path, PathBuf},
    process::Command,
};
use zip::ZipArchive;

#[cfg(unix)]
use daemonize::Daemonize;

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
