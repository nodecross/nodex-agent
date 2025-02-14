use crate::config::get_config;
use crate::validator::sigstore::{BundleVerifier, TrustRootDownloader, Verifier, VerifyError};
use bytes::Bytes;
use flate2::{read::GzDecoder, write::GzEncoder, Compression};
use glob::glob;
use std::{
    fs::{self, File},
    io::{self, Cursor},
    path::{Path, PathBuf},
    time::SystemTime,
};
use tar::{Archive, Builder, Header};
#[cfg(unix)]
use users::{get_current_gid, get_current_uid};
use zip::{result::ZipError, ZipArchive};
use walkdir::WalkDir;

#[derive(Debug, thiserror::Error)]
pub enum ResourceError {
    #[error("Failed to download the file from {0}")]
    DownloadFailed(String),
    #[error("Failed to write to output path: {0}")]
    IoError(#[from] io::Error),
    #[error("Failed to extract zip file")]
    ZipError(#[from] ZipError),
    #[error("Failed to create tarball: {0}")]
    TarError(String),
    #[error("Failed to delete files in {0}")]
    RemoveFailed(String),
    #[error("Rollback failed: {0}")]
    RollbackFailed(String),
    #[error("Failed to verify: {0}")]
    VerifyError(VerifyError),
    #[error("File not found: {0}")]
    FileNotFound(String),
    #[error["Failed to Move: {0}"]]
    MoveFailed(String),
}

// ref: https://stackoverflow.com/questions/26958489/how-to-copy-a-folder-recursively-in-rust
fn copy_dir_all(src: impl AsRef<Path>, dst: impl AsRef<Path>) -> io::Result<()> {
    if !fs::metadata(&src)?.is_dir() {
        if !fs::exists(&dst)? {
            fs::copy(&src, &dst)?;
        } else if fs::metadata(&dst)?.is_dir() {
            let name = src
                .as_ref()
                .file_name()
                .ok_or(io::Error::new(io::ErrorKind::IsADirectory, "Invalid path"))?;
            fs::copy(&src, dst.as_ref().join(name))?;
        } else {
            fs::copy(&src, &dst)?;
        }
        return Ok(());
    }

    fs::create_dir_all(&dst)?;
    for entry in fs::read_dir(src)? {
        let entry = entry?;
        let ty = entry.file_type()?;
        if ty.is_dir() {
            copy_dir_all(entry.path(), dst.as_ref().join(entry.file_name()))?;
        } else {
            fs::copy(entry.path(), dst.as_ref().join(entry.file_name()))?;
        }
    }
    Ok(())
}

#[trait_variant::make(Send)]
pub trait ResourceManagerTrait: Send + Sync {
    fn backup(&self) -> Result<(), ResourceError>;

    fn rollback(&self, backup_file: &Path) -> Result<(), ResourceError>;

    fn tmp_path(&self) -> &PathBuf;

    fn agent_path(&self) -> &PathBuf;

    async fn download_update_resources(
        &self,
        binary_url: &str,
        output_path: Option<impl AsRef<Path> + Send>,
    ) -> Result<(), ResourceError> {
        async move {
            let output_path = output_path.map(|x| x.as_ref().to_path_buf());
            let download_path = output_path.as_ref().unwrap_or(self.tmp_path());

            let response = reqwest::get(binary_url)
                .await
                .map_err(|_| ResourceError::DownloadFailed(binary_url.to_string()))?;
            let content = response
                .bytes()
                .await
                .map_err(|_| ResourceError::DownloadFailed(binary_url.to_string()))?;

            self.extract_zip(content, download_path)?;

            let nodex_agent_path = self.find_file(&download_path, "nodex-agent")
            .ok_or_else(|| ResourceError::FileNotFound("nodex-agent".to_string()))?;
            let nodex_agent_bundle_path = self.find_file(&download_path, "nodex-agent.bundle")
            .ok_or_else(|| ResourceError::FileNotFound("nodex-agent.bundle".to_string()))?;
    
            fs::rename(&nodex_agent_path, download_path.join("nodex-agent"))
                .map_err(|e| ResourceError::MoveFailed(e.to_string()))?;
            fs::rename(&nodex_agent_bundle_path, download_path.join("nodex-agent.bundle"))
                .map_err(|e| ResourceError::MoveFailed(e.to_string()))?;

            Ok(())
        }
    }

    fn get_paths_to_backup(&self) -> Result<Vec<PathBuf>, ResourceError> {
        let config = get_config().lock().unwrap();
        Ok(vec![self.agent_path().clone(), config.config_dir.clone()])
    }

    fn find_file(&self, dir: &PathBuf, target: &str) -> Option<PathBuf> {
        for entry in WalkDir::new(dir) {
            if let Ok(entry) = entry {
                if entry.file_name() == target {
                    return Some(entry.into_path());
                }
            }
        }
        None
    }

    fn collect_downloaded_bundles(&self) -> Vec<PathBuf> {
        let pattern = self
            .tmp_path()
            .join("bundles")
            .join("*.yml")
            .to_string_lossy()
            .into_owned();

        match glob(&pattern) {
            Ok(paths) => paths.filter_map(Result::ok).collect(),
            Err(_) => Vec::new(),
        }
    }

    fn get_latest_backup(&self) -> Option<PathBuf> {
        fs::read_dir(self.tmp_path())
            .ok()?
            .filter_map(|entry| entry.ok().map(|e| e.path()))
            .filter(|path| {
                path.is_file() && path.extension().and_then(|ext| ext.to_str()) == Some("gz")
            })
            .max_by_key(|path| {
                path.metadata()
                    .and_then(|meta| meta.modified())
                    .unwrap_or(SystemTime::UNIX_EPOCH)
            })
    }

    fn extract_zip(&self, archive_data: Bytes, output_path: &Path) -> Result<(), ResourceError> {
        let cursor = Cursor::new(archive_data);
        let mut archive = ZipArchive::new(cursor)?;

        for i in 0..archive.len() {
            let mut file = archive.by_index(i)?;
            let file_path = output_path.join(file.mangled_name());

            if file.is_file() {
                if let Some(parent) = file_path.parent() {
                    fs::create_dir_all(parent)?;
                }
                let _ = fs::remove_file(&file_path);
                let mut output_file = File::create(&file_path)?;
                io::copy(&mut file, &mut output_file)?;
                #[cfg(unix)]
                if let Some(file_name) = file_path.file_name() {
                    if file_name == "nodex-agent" {
                        crate::unix_utils::change_to_executable(&file_path)?;
                    }
                }
            } else if file.is_dir() {
                fs::create_dir_all(&file_path)?;
            }
        }

        Ok(())
    }

    async fn verify(&self, downloaded_path: &Path) -> Result<(), ResourceError> {
        async move {
            BundleVerifier::new(TrustRootDownloader)
                .verify(
                    self.tmp_path(),
                    downloaded_path.join("nodex-agent.bundle"),
                    downloaded_path.join("nodex-agent"),
                    "https://github.com/nodecross/nodex/blob/main/.github/workflows/release.yml@refs/heads/main",
                    "https://token.actions.githubusercontent.com"
                )
                .await
                .map_err(ResourceError::VerifyError)?;

            log::info!("Verified successfully");

            Ok(())
        }
    }

    fn remove_directory(&self, path: &Path) -> Result<(), io::Error> {
        if !path.exists() {
            return Ok(());
        }

        if path.is_dir() {
            fs::remove_dir_all(path).map_err(|e| {
                io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    format!("Failed to remove directory {:?}: {}", path, e),
                )
            })?;
        } else {
            fs::remove_file(path).map_err(|e| {
                io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    format!("Failed to remove file {:?}: {}", path, e),
                )
            })?;
        }
        Ok(())
    }

    fn remove(&self) -> Result<(), ResourceError> {
        for entry in fs::read_dir(self.tmp_path())
            .map_err(|e| ResourceError::RemoveFailed(format!("Failed to read directory: {}", e)))?
        {
            let entry = entry.map_err(|e| {
                ResourceError::RemoveFailed(format!("Failed to access entry: {}", e))
            })?;
            let entry_path = entry.path();

            self.remove_directory(&entry_path).map_err(|e| {
                ResourceError::RemoveFailed(format!(
                    "Failed to remove path {:?}: {}",
                    entry_path, e
                ))
            })?;
        }
        Ok(())
    }
}

#[cfg(unix)]
pub struct UnixResourceManager {
    tmp_path: PathBuf,
    agent_path: PathBuf,
}

#[cfg(unix)]
impl ResourceManagerTrait for UnixResourceManager {
    fn tmp_path(&self) -> &PathBuf {
        &self.tmp_path
    }

    fn agent_path(&self) -> &PathBuf {
        &self.agent_path
    }

    fn backup(&self) -> Result<(), ResourceError> {
        let paths_to_backup = self.get_paths_to_backup()?;
        let metadata = self.generate_metadata(&paths_to_backup)?;
        let tar_gz_path = self.create_tar_gz_with_metadata(&metadata)?;
        log::info!("Backup created successfully at {:?}", tar_gz_path);
        Ok(())
    }

    fn rollback(&self, backup_file: &Path) -> Result<(), ResourceError> {
        let temp_dir = self.extract_tar_to_temp(backup_file)?;
        // Might be safer to check for the existence of config.json and binary
        let metadata = self.read_metadata(&temp_dir)?;
        self.move_files_to_original_paths(&temp_dir, &metadata)?;

        log::info!("Rollback completed successfully from {:?}", backup_file);
        Ok(())
    }
}

#[cfg(unix)]
impl UnixResourceManager {
    pub fn new(agent_path: impl AsRef<Path>) -> Self {
        let tmp_path = if PathBuf::from("/home/nodex/").exists() {
            PathBuf::from("/home/nodex/tmp")
        } else if PathBuf::from("/tmp/nodex").exists() || fs::create_dir_all("/tmp/nodex").is_ok() {
            PathBuf::from("/tmp/nodex")
        } else {
            PathBuf::from("/tmp")
        };

        if !tmp_path.exists() {
            fs::create_dir_all(&tmp_path).expect("Failed to create tmp dir");
        }

        Self {
            tmp_path,
            agent_path: agent_path.as_ref().into(),
        }
    }

    fn generate_metadata(
        &self,
        src_paths: &[PathBuf],
    ) -> Result<Vec<(PathBuf, PathBuf)>, ResourceError> {
        src_paths
            .iter()
            .map(|path| {
                let relative_path = path.strip_prefix("/").unwrap_or(path).to_path_buf();
                Ok((path.clone(), relative_path))
            })
            .collect()
    }

    fn create_tar_gz_with_metadata(
        &self,
        metadata: &[(PathBuf, PathBuf)],
    ) -> Result<PathBuf, ResourceError> {
        let timestamp = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map_err(|e| {
                ResourceError::TarError(format!("Failed to get current timestamp: {}", e))
            })?
            .as_secs();

        let dest_path = self
            .tmp_path
            .join(format!("nodex_backup_{}.tar.gz", timestamp));

        let tar_gz_file = File::create(&dest_path)
            .map_err(|e| ResourceError::IoError(io::Error::new(io::ErrorKind::Other, e)))?;
        let mut encoder = GzEncoder::new(tar_gz_file, Compression::default());
        {
            let mut tar_builder = Builder::new(&mut encoder);

            self.add_files_to_tar(&mut tar_builder, metadata)?;
            self.add_metadata_to_tar(&mut tar_builder, metadata, timestamp)?;
            tar_builder
                .finish()
                .map_err(|e| ResourceError::TarError(format!("Failed to finish tarball: {}", e)))?;
        }

        encoder.try_finish().map_err(|e| {
            ResourceError::TarError(format!("Failed to finalize tar.gz file: {}", e))
        })?;

        Ok(dest_path)
    }

    fn add_files_to_tar<W: std::io::Write>(
        &self,
        tar_builder: &mut Builder<W>,
        metadata: &[(PathBuf, PathBuf)],
    ) -> Result<(), ResourceError> {
        for (original_path, relative_path) in metadata {
            if original_path.is_dir() {
                tar_builder
                    .append_dir_all(relative_path, original_path)
                    .map_err(|e| {
                        ResourceError::TarError(format!(
                            "Failed to append directory {:?}: {}",
                            original_path, e
                        ))
                    })?;
            } else if original_path.is_file() {
                tar_builder
                    .append_path_with_name(original_path, relative_path)
                    .map_err(|e| {
                        ResourceError::TarError(format!(
                            "Failed to append file {:?}: {}",
                            original_path, e
                        ))
                    })?;
            }
        }
        Ok(())
    }

    fn add_metadata_to_tar<W: std::io::Write>(
        &self,
        tar_builder: &mut Builder<W>,
        metadata: &[(PathBuf, PathBuf)],
        timestamp: u64,
    ) -> Result<(), ResourceError> {
        let uid = get_current_uid();
        let gid = get_current_gid();

        let metadata: Vec<_> = metadata
            .iter()
            .map(|(x, y)| (x.as_path().to_str(), y.as_path().to_str()))
            .collect();
        let metadata_json = serde_json::to_string(&metadata)
            .map_err(|e| ResourceError::TarError(format!("Failed to serialize metadata: {}", e)))?;

        let mut header = Header::new_gnu();
        header
            .set_path("backup_metadata.json")
            .map_err(|e| ResourceError::TarError(format!("Failed to set header path: {}", e)))?;
        header.set_size(metadata_json.len() as u64);
        header.set_mode(0o644);
        header.set_mtime(timestamp);
        header.set_uid(uid as u64);
        header.set_gid(gid as u64);
        header.set_cksum();

        tar_builder
            .append_data(
                &mut header,
                "backup_metadata.json",
                metadata_json.as_bytes(),
            )
            .map_err(|e| ResourceError::TarError(format!("Failed to add metadata: {}", e)))?;

        Ok(())
    }

    fn extract_tar_to_temp(&self, backup_file: &Path) -> Result<PathBuf, ResourceError> {
        let file = File::open(backup_file).map_err(|e| {
            ResourceError::RollbackFailed(format!(
                "Failed to open backup file {:?}: {}",
                backup_file, e
            ))
        })?;
        let decompressed = GzDecoder::new(file);
        let mut archive = Archive::new(decompressed);

        let temp_dir = PathBuf::from("/tmp/restore_temp");
        std::fs::create_dir_all(&temp_dir).map_err(|e| {
            ResourceError::RollbackFailed(format!(
                "Failed to create temp directory {:?}: {}",
                temp_dir, e
            ))
        })?;

        archive.unpack(&temp_dir).map_err(|e| {
            ResourceError::RollbackFailed(format!(
                "Failed to unpack backup archive to temp directory {:?}: {}",
                temp_dir, e
            ))
        })?;

        Ok(temp_dir)
    }

    fn read_metadata(&self, temp_dir: &Path) -> Result<Vec<(PathBuf, PathBuf)>, ResourceError> {
        let metadata_file = temp_dir.join("backup_metadata.json");
        let metadata_contents = std::fs::read_to_string(&metadata_file).map_err(|e| {
            ResourceError::RollbackFailed(format!(
                "Failed to read metadata file {:?}: {}",
                metadata_file, e
            ))
        })?;
        let metadata = serde_json::from_str(&metadata_contents).map_err(|e| {
            ResourceError::RollbackFailed(format!(
                "Failed to parse metadata file {:?}: {}",
                metadata_file, e
            ))
        })?;
        Ok(metadata)
    }

    fn move_files_to_original_paths(
        &self,
        temp_dir: &Path,
        metadata: &[(PathBuf, PathBuf)],
    ) -> Result<(), ResourceError> {
        for (original_path, relative_path) in metadata {
            let temp_path = temp_dir.join(relative_path);
            if temp_path.exists() {
                if original_path.exists() {
                    self.remove_directory(original_path).map_err(|e| {
                        ResourceError::RollbackFailed(format!(
                            "Failed to remove existing path {:?}: {}",
                            original_path, e
                        ))
                    })?;
                }
                // fs::rename does not work with another partition
                copy_dir_all(&temp_path, original_path).map_err(|e| {
                    ResourceError::RollbackFailed(format!(
                        "Failed to move file from {:?} to {:?}: {}",
                        temp_path, original_path, e
                    ))
                })?;
            }
        }
        Ok(())
    }
}

#[cfg(windows)]
pub struct WindowsResourceManager {
    tmp_path: PathBuf,
}

#[cfg(windows)]
impl ResourceManagerTrait for WindowsResourceManager {
    fn tmp_path(&self) -> &PathBuf {
        &self.tmp_path
    }

    fn agent_path(&self) -> &PathBuf {
        unimplemented!()
    }

    fn backup(&self) -> Result<(), ResourceError> {
        unimplemented!()
    }

    fn rollback(&self, backup_file: &Path) -> Result<(), ResourceError> {
        unimplemented!()
    }
}

#[cfg(windows)]
impl WindowsResourceManager {
    pub fn new() -> Self {
        // provisional implementation
        let tmp_path = PathBuf::from("C:\\Temp\\nodex-agent");
        Self { tmp_path }
    }
}

#[cfg(windows)]
impl Default for WindowsResourceManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use filetime;
    use mockito;
    use std::fs::{self, File};
    use std::io::Write;
    use std::time::{Duration, SystemTime};
    use tempfile::{tempdir, NamedTempFile};
    use zip::{
        write::{ExtendedFileOptions, FileOptions},
        CompressionMethod, ZipWriter,
    };

    impl Default for UnixResourceManager {
        fn default() -> Self {
            Self::new(std::env::current_exe().unwrap())
        }
    }

    fn create_sample_zip() -> NamedTempFile {
        let file = NamedTempFile::new().unwrap();
        let mut zip = ZipWriter::new(file.reopen().unwrap());

        let options: FileOptions<ExtendedFileOptions> = FileOptions::default()
            .compression_method(CompressionMethod::Stored)
            .unix_permissions(0o644);

        zip.start_file("sample.txt", options).unwrap();
        zip.write_all(b"This is a test file.").unwrap();
        zip.finish().unwrap();

        file
    }

    #[tokio::test]
    async fn test_download_update_resources() {
        let sample_zip = create_sample_zip();
        let zip_data = fs::read(sample_zip.path()).unwrap();

        let mut server = mockito::Server::new_async().await;
        let path = "/test.zip";
        let _mock = server
            .mock("GET", path)
            .with_status(200)
            .with_header("content-type", "application/zip")
            .with_body(zip_data)
            .create();

        let resource_manager = UnixResourceManager::default();
        let temp_dir = tempdir().unwrap();
        let output_path = temp_dir.path().to_path_buf();

        let url = server.url() + path;
        let result = resource_manager
            .download_update_resources(&url, Some(&output_path))
            .await;

        assert!(
            result.is_ok(),
            "Expected download_update_resources to succeed"
        );

        let extracted_file = output_path.join("sample.txt");
        assert!(extracted_file.exists(), "Expected extracted file to exist");

        let content = fs::read_to_string(extracted_file).unwrap();
        assert_eq!(
            content.trim(),
            "This is a test file.",
            "File content mismatch"
        );
    }

    #[test]
    fn test_collect_downloaded_bundles() {
        let temp_dir = tempdir().unwrap();
        let bundles_dir = temp_dir.path().join("bundles");
        fs::create_dir_all(&bundles_dir).unwrap();

        let bundle_file = bundles_dir.join("bundle1.yml");
        File::create(&bundle_file).unwrap();

        let resource_manager = UnixResourceManager {
            tmp_path: temp_dir.path().to_path_buf(),
            ..Default::default()
        };

        let collected_bundles = resource_manager.collect_downloaded_bundles();

        assert_eq!(
            collected_bundles.len(),
            1,
            "Expected exactly one bundle file"
        );
        assert_eq!(
            collected_bundles[0], bundle_file,
            "Unexpected bundle file path"
        );
    }

    #[test]
    fn test_get_latest_backup() {
        let temp_dir = tempdir().unwrap();

        let old_file = temp_dir.path().join("old_backup.gz");
        let new_file = temp_dir.path().join("new_backup.gz");

        File::create(&old_file).unwrap();
        File::create(&new_file).unwrap();
        let new_time = SystemTime::now();
        let old_time = new_time - Duration::from_secs(60);

        filetime::set_file_mtime(&old_file, filetime::FileTime::from_system_time(old_time))
            .unwrap();
        filetime::set_file_mtime(&new_file, filetime::FileTime::from_system_time(new_time))
            .unwrap();

        let resource_manager = UnixResourceManager {
            tmp_path: temp_dir.path().to_path_buf(),
            ..Default::default()
        };

        let latest_backup = resource_manager.get_latest_backup();

        assert_eq!(
            latest_backup,
            Some(new_file),
            "Expected new_backup.gz to be the latest"
        );
    }

    #[test]
    fn test_backup() {
        let temp_dir = tempdir().unwrap();
        let resource_manager = UnixResourceManager {
            tmp_path: temp_dir.path().to_path_buf(),
            ..Default::default()
        };

        let result = resource_manager.backup();
        assert!(result.is_ok(), "Expected backup to succeed");

        let backups: Vec<_> = fs::read_dir(temp_dir.path())
            .unwrap()
            .filter_map(|entry| entry.ok())
            .filter(|entry| entry.path().extension().and_then(|e| e.to_str()) == Some("gz"))
            .collect();

        assert_eq!(backups.len(), 1, "Expected exactly one backup file");
    }

    #[test]
    fn test_rollback() {
        let temp_dir = tempdir().unwrap();
        let resource_manager = UnixResourceManager {
            tmp_path: temp_dir.path().to_path_buf(),
            ..Default::default()
        };

        let _ = resource_manager.backup();
        let latest_backup = resource_manager.get_latest_backup();

        assert!(latest_backup.is_some(), "Expected a backup to exist");
        if let Some(backup) = latest_backup {
            let result: Result<(), ResourceError> = resource_manager.rollback(&backup);
            println!("Result: {:?}", result);
            assert!(result.is_ok(), "Expected rollback to succeed");
        }
    }

    #[test]
    fn test_remove() {
        let temp_dir = tempdir().unwrap();

        let resource_manager = UnixResourceManager {
            tmp_path: temp_dir.path().to_path_buf(),
            ..Default::default()
        };

        let dummy_file = temp_dir.path().join("dummy_file.txt");
        File::create(&dummy_file).unwrap();

        assert!(
            dummy_file.exists(),
            "Dummy file should exist before removal"
        );

        let result = resource_manager.remove();
        assert!(result.is_ok(), "Expected remove to succeed");

        assert!(!dummy_file.exists(), "Dummy file should be removed");
    }
}
