use base64::{engine::general_purpose::STANDARD as BASE64_STD_ENGINE, Engine as _};
use sigstore::{
    bundle::verify::{policy, VerificationPolicy},
    cosign::{
        bundle::SignedArtifactBundle,
        {client::Client, CosignCapabilities}
    },
    crypto::{CosignVerificationKey, SigningScheme},
    errors::SigstoreError,
    trust::{
        TrustRoot,
        sigstore::SigstoreTrustRoot
    }
};
use std::path::{Path, PathBuf};
use x509_cert;

#[derive(Debug, thiserror::Error)]
pub enum VerifyError {
    #[error("Download failed: {0}")]
    DownloadFailed(SigstoreError),
    #[error("TUF metadata error: {0}")]
    TufMetadataError(SigstoreError),
    #[error("Parse bundle error: {0}")]
    CastBundleFailed(serde_json::Error),
    #[error("Verify bundle error: {0}")]
    CastDerCertificate(SigstoreError),
    #[error("failed to decode base64: {0}")]
    Base64DecodeError(#[from] base64::DecodeError),
    #[error("failed to convert decoded bytes to UTF-8 string: {0}")]
    Utf8Error(#[from] std::string::FromUtf8Error),
    #[error("failed to load X.509 bundle.cert from PEM data: {0}")]
    X509CertError(#[from] x509_cert::der::Error),
    #[error("failed to read file: {0}")]
    ReadFileError(#[source] std::io::Error),
    #[error("failed to verify: {0}")]
    VerifyFailed(SigstoreError),
    #[error("failed to create sigstore directory: {0}")]
    CreateSigstoreDirError(#[source] std::io::Error),
    #[error("rekor key empty")]
    RekorKeyEmpty,
    #[error("failed to verify bundle: {0}")]
    VerifyBundleFailed(#[source] SigstoreError),
}

#[trait_variant::make(Send)]
pub trait TrustRootRepository: Send + Sync {
    async fn get(&self, sigstore_dir: &Path) -> Result<SigstoreTrustRoot, VerifyError>;
}
pub struct TrustRootDownloader;

impl TrustRootRepository for TrustRootDownloader {
    async fn get(&self, sigstore_dir: &Path) -> Result<SigstoreTrustRoot, VerifyError> {
        if std::fs::exists(sigstore_dir).unwrap_or(false) {
            std::fs::remove_dir_all(sigstore_dir).unwrap_or_default();
        }
        std::fs::create_dir(sigstore_dir).map_err(VerifyError::CreateSigstoreDirError)?;
        SigstoreTrustRoot::new(Some(sigstore_dir))
            .await
            .map_err(VerifyError::DownloadFailed)
    }
}

#[trait_variant::make(Send)]
pub trait Verifier: Send + Sync {
    async fn verify(
        &self,
        tmp_path: &Path,
        bundle_json: PathBuf,
        blob_path: PathBuf,
        identity: &str,
        issuer: &str,
    ) -> Result<(), VerifyError>;

    fn parse_x509_cert(&self, cert: &str) -> Result<Vec<x509_cert::Certificate>, VerifyError>;
}

pub struct BundleVerifier<R: TrustRootRepository + Sync + Send> {
    repository: R,
}

impl<R: TrustRootRepository + Sync + Send> BundleVerifier<R> {
    pub fn new(repository: R) -> Self {
        Self { repository }
    }
}

impl<R: TrustRootRepository + Sync + Send> Verifier for BundleVerifier<R> {
    async fn verify(
        &self,
        tmp_path: &Path,
        bundle_json: PathBuf,
        blob_path: PathBuf,
        identity: &str,
        issuer: &str,
    ) -> Result<(), VerifyError> {
        let blob = std::fs::read(blob_path).map_err(VerifyError::ReadFileError)?;
        let bundle_json_content =
            std::fs::read_to_string(bundle_json).map_err(VerifyError::ReadFileError)?;

        let sigstore_dir = tmp_path.join(".sigstore");
        let trust_root = self.repository.get(&sigstore_dir).await?;
        let rekor_keys = trust_root
            .rekor_keys()
            .map_err(VerifyError::TufMetadataError)?;
        let cosign_verification_key = if rekor_keys.is_empty() {
            return Err(VerifyError::RekorKeyEmpty);
        } else {
            CosignVerificationKey::from_der(rekor_keys[0], &SigningScheme::default())
                .map_err(VerifyError::CastDerCertificate)
        }?;

        let bundle =
            SignedArtifactBundle::new_verified(&bundle_json_content, &cosign_verification_key)
                .map_err(VerifyError::VerifyBundleFailed)?;

        let certificate_chain = self.parse_x509_cert(bundle.cert.as_str())?;

        let id_policy = policy::Identity::new(identity, issuer);
        id_policy
            .verify(&certificate_chain[0])
            .expect("Failed to verify");

        Client::verify_blob(&bundle.cert, &bundle.base64_signature.trim(), &blob)
            .map_err(VerifyError::VerifyFailed)
    }

    fn parse_x509_cert(&self, cert: &str) -> Result<Vec<x509_cert::Certificate>, VerifyError> {
        let cert_data = BASE64_STD_ENGINE.decode(cert)?;
        let cert_str = String::from_utf8(cert_data)?;
        let cert_chain = x509_cert::Certificate::load_pem_chain(cert_str.as_bytes())?;
        Ok(cert_chain)
    }
}

// async fn download_sigstore_trust_root(
//     sigstore_dir: &Path,
// ) -> Result<SigstoreTrustRoot, VerifyError> {
//     if std::fs::exists(&sigstore_dir).unwrap_or(false) {
//         println!("Removing cache directory");
//         std::fs::remove_dir_all(&sigstore_dir).unwrap_or_default();
//     }
//     std::fs::create_dir(&sigstore_dir).map_err(|e| VerifyError::CreateSigstoreDirError(e))?;
//     SigstoreTrustRoot::new(Some(sigstore_dir))
//         .await
//         .map_err(|e| VerifyError::DownloadFailed(e))
// }

// fn parse_x509_cert(cert: &str) -> Result<Vec<x509_cert::Certificate>, VerifyError> {
//     let cert_data = BASE64_STD_ENGINE.decode(cert)?;
//     let cert = String::from_utf8(cert_data)?;
//     let cert_chain = x509_cert::Certificate::load_pem_chain(cert.as_bytes())?;
//     Ok(cert_chain)
// }

// pub async fn verify(
//     tmp_path: &Path,
//     bundle_json: &Path,
//     blob_path: &Path,
//     identity: &str,
//     issuer: &str,
// ) -> Result<(), VerifyError> {
//     // let identity = "https://github.com/da13da/verify-by-sigstore/.github/workflows/cosign-with-github.yml@refs/heads/main";
//     // let issuer = "https://token.actions.githubusercontent.com";
//     let blob = std::fs::read(blob_path).map_err(|e| VerifyError::ReadFileError(e))?;
//     let bundle_json =
//         std::fs::read_to_string(bundle_json).map_err(|e| VerifyError::ReadFileError(e))?;

//     let sigstore_dir = tmp_path.join(".sigstore");
//     let trust_root = download_sigstore_trust_root(&sigstore_dir).await?;

//     let rekor_keys = trust_root
//         .rekor_keys()
//         .map_err(|e| VerifyError::TufMetadataError((e)))?;
//     let cosign_verification_key = if rekor_keys.is_empty() {
//         return Err(VerifyError::RekorKeyEmpty);
//     } else {
//         CosignVerificationKey::from_der(rekor_keys[0], &SigningScheme::default())
//             .map_err(|e| VerifyError::CastDerCertificate(e))
//     }?;

//     let bundle = SignedArtifactBundle::new_verified(&bundle_json, &cosign_verification_key)
//         .map_err(|e| VerifyError::VerifyBundleFailed(e))?;
//     let certificate_chain = parse_x509_cert(bundle.cert.as_str())?;

//     let id_policy = policy::Identity::new(identity, issuer);
//     id_policy
//         .verify(&certificate_chain[0])
//         .expect("Failed to verify");

//     Client::verify_blob(&bundle.cert, &bundle.base64_signature.trim(), &blob)
//         .map_err(|e| VerifyError::VerifyFailed(e))
// }
