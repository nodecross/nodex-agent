use base64::{engine::general_purpose::STANDARD as BASE64_STD_ENGINE, Engine as _};
use sigstore::{
    bundle::verify::{policy, VerificationPolicy},
    cosign::{
        bundle::SignedArtifactBundle,
        {client::Client, CosignCapabilities},
    },
    crypto::{CosignVerificationKey, SigningScheme},
    errors::SigstoreError,
    trust::{sigstore::SigstoreTrustRoot, TrustRoot},
};
use std::path::{Path, PathBuf};
use x509_cert;

#[derive(Debug, thiserror::Error)]
pub enum VerifyError {
    #[error("failed to download trust root metadata: {0}")]
    TrustRootDownloadError(#[source] SigstoreError),
    #[error("failed to load TUF metadata: {0}")]
    TufMetadataLoadError(#[source] SigstoreError),
    #[error("failed to parse signed artifact bundle JSON: {0}")]
    BundleParseError(serde_json::Error),
    #[error("failed to convert DER certificate to verification key: {0}")]
    VerificationKeyConversionError(#[source] SigstoreError),
    #[error("failed to decode base64 certificate: {0}")]
    Base64DecodeError(#[from] base64::DecodeError),
    #[error("failed to convert decoded certificate to UTF-8 string: {0}")]
    Utf8ConversionError(#[from] std::string::FromUtf8Error),
    #[error("failed to load X.509 certificate chain from PEM data: {0}")]
    X509CertLoadError(#[from] x509_cert::der::Error),
    #[error("failed to read file: {0}")]
    FileReadError(#[source] std::io::Error),
    #[error("failed to verify blob signature: {0}")]
    BlobVerificationError(#[source] SigstoreError),
    #[error("failed to create sigstore directory: {0}")]
    SigstoreDirCreationError(#[source] std::io::Error),
    #[error("no rekor keys found in the trust root")]
    MissingRekorKey,
    #[error("failed to verify signed artifact bundle: {0}")]
    BundleVerificationError(#[source] SigstoreError),
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
        log::info!("Downloading TUF metadata to {:?}", sigstore_dir);
        std::fs::create_dir(sigstore_dir).map_err(VerifyError::SigstoreDirCreationError)?;
        SigstoreTrustRoot::new(Some(sigstore_dir))
            .await
            .map_err(VerifyError::TrustRootDownloadError)
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

    fn decode_cert(&self, cert: &str) -> Result<String, VerifyError>;
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
        log::info!("tmp_path: {:?}", tmp_path);
        log::info!("bundle_json: {:?}", bundle_json);
        let blob = std::fs::read(blob_path).map_err(VerifyError::FileReadError)?;
        let bundle_json_content =
            std::fs::read_to_string(bundle_json).map_err(VerifyError::FileReadError)?;

        let sigstore_dir = tmp_path.join(".sigstore");
        let trust_root = self.repository.get(&sigstore_dir).await?;
        let rekor_keys = trust_root
            .rekor_keys()
            .map_err(VerifyError::TufMetadataLoadError)?;
        let cosign_verification_key = if rekor_keys.is_empty() {
            return Err(VerifyError::MissingRekorKey);
        } else {
            CosignVerificationKey::from_der(rekor_keys[0], &SigningScheme::default())
                .map_err(VerifyError::VerificationKeyConversionError)
        }?;

        let bundle =
            SignedArtifactBundle::new_verified(&bundle_json_content, &cosign_verification_key)
                .map_err(VerifyError::BundleVerificationError)?;

        let decoded_cert = self.decode_cert(bundle.cert.as_str())?;
        let cert_chain = x509_cert::Certificate::load_pem_chain(decoded_cert.as_bytes()).map_err(|e| VerifyError::X509CertLoadError(e))?;

        let id_policy = policy::Identity::new(identity, issuer);
        id_policy
            .verify(&cert_chain[0])
            .expect("Failed to verify");

        Client::verify_blob(&decoded_cert, bundle.base64_signature.trim(), &blob)
            .map_err(VerifyError::BundleVerificationError)
    }

    fn decode_cert(&self, cert: &str) -> Result<String, VerifyError> {
        let cert_data = BASE64_STD_ENGINE.decode(cert)?;
        let cert_str = String::from_utf8(cert_data)?;
        Ok(cert_str)
    }
}
