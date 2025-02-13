use super::super::service_impl::DidWebvhServiceImpl;
use crate::did_webvh::domain::crypto::crypto_utils::multibase_encode;
use crate::did_webvh::domain::did_document::{DidDocument, VerificationMethod};
use crate::did_webvh::domain::did_log_entry::DidLogEntry;
use crate::did_webvh::infra::did_webvh_data_store::DidWebvhDataStore;
use crate::keyring::{
    jwk::Jwk,
    keypair::{KeyPair, KeyPairing},
};

use std::convert::TryInto;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum DidWebvhIdentifierError<StudioClientError: std::error::Error> {
    #[error("Failed to convert to JWK: {0}")]
    Jwk(#[from] crate::keyring::jwk::K256ToJwkError),
    #[error("Failed to parse body: {0}")]
    BodyParse(#[from] serde_json::Error),
    #[error("Failed to create identifier. response: {0}")]
    DidWebvhRequestFailed(String),
    #[error("Failed to send request: {0}")]
    DidWebvhHttpClient(StudioClientError),
    #[error("Failed to create identifier: {0}")]
    DidWebvhCreateLogEntryFailed(#[from] crate::did_webvh::domain::did_log_entry::DidLogEntryError),
    #[error("Failed to generate hash : {0}")]
    DidWebvhCreateGenerateHashFailed(
        #[from] crate::did_webvh::domain::crypto::crypto_utils::CryptoError,
    ),
}

#[trait_variant::make(Send)]
pub trait DidWebvhControllerService: Sync {
    type DidWebvhIdentifierError: std::error::Error + Send + Sync;
    async fn create_identifier(
        &self,
        path: &str,
        enable_prerotation: bool,
        keyring: KeyPairing,
    ) -> Result<DidDocument, Self::DidWebvhIdentifierError>;
    async fn update_identifier(
        &self,
        path: &str,
        keyring: KeyPairing,
    ) -> Result<DidDocument, Self::DidWebvhIdentifierError>;
    async fn deactivate_identifier(
        &self,
        path: &str,
        keyring: KeyPairing,
    ) -> Result<DidDocument, Self::DidWebvhIdentifierError>;
}

impl<C> DidWebvhControllerService for DidWebvhServiceImpl<C>
where
    C: DidWebvhDataStore + Send + Sync,
    C::Error: Send + Sync,
{
    type DidWebvhIdentifierError = DidWebvhIdentifierError<C::Error>;

    async fn create_identifier(
        &self,
        path: &str,
        enable_prerotation: bool,
        keyring: KeyPairing,
    ) -> Result<DidDocument, Self::DidWebvhIdentifierError> {
        let sign_key_jwk: Jwk = keyring.sign.get_public_key().try_into().map_err(|_| {
            DidWebvhIdentifierError::Jwk(crate::keyring::jwk::K256ToJwkError::PointsInvalid)
        })?;
        let encrypt_key_jwk: Jwk =
            <x25519_dalek::PublicKey as Into<Jwk>>::into(keyring.encrypt.get_public_key());

        let mut log_entry = DidLogEntry::new(path)?;
        let update_keypair = keyring.update;
        let update_sec_key = update_keypair.get_secret_key().to_bytes();
        let update_pub_key = multibase_encode(&update_keypair.get_public_key().to_sec1_bytes());
        let update_keys = vec![update_pub_key.clone()];
        log_entry.parameters.update_keys = Some(update_keys);

        // if prerotation is enabled, add the prerotation key to the next_key_hashes
        if enable_prerotation {
            let prerotation_pub_key =
                multibase_encode(&keyring.recovery.get_public_key().to_sec1_bytes());
            let prerotation_keys = vec![prerotation_pub_key];
            let next_key_hases = log_entry.calc_next_key_hash(&prerotation_keys)?;
            log_entry.parameters.next_key_hashes = Some(next_key_hases);
        }

        let sign_verification_method = VerificationMethod {
            id: format!("{}#{}", log_entry.state.id, "signingKey"),
            r#type: "EcdsaSecp256k1VerificationKey2019".to_string(),
            controller: log_entry.state.id.clone(),
            public_key_jwk: Some(sign_key_jwk),
            blockchain_account_id: None,
            public_key_multibase: None,
        };
        log_entry
            .state
            .add_verification_method(sign_verification_method);

        let encrypt_verification_method = VerificationMethod {
            id: format!("{}#{}", log_entry.state.id, "encryptionKey"),
            r#type: "X25519KeyAgreementKey2019".to_string(),
            controller: log_entry.state.id.clone(),
            public_key_jwk: Some(encrypt_key_jwk),
            blockchain_account_id: None,
            public_key_multibase: None,
        };
        log_entry
            .state
            .add_verification_method(encrypt_verification_method);

        let scid = log_entry.calc_entry_hash()?;
        log_entry.replace_placeholder_to_id(&scid)?;

        log_entry.generate_proof(&update_sec_key, &update_pub_key)?;

        // convert log entry to jsonl file format
        let entry = serde_json::to_string(&log_entry)?
            .replace("\n", "")
            .replace(" ", "");

        let body = format!("{}\n", entry);

        let response = self
            .data_store
            .post(path, &body)
            .await
            .map_err(|e| DidWebvhIdentifierError::DidWebvhRequestFailed(e.to_string()))?;
        if response.status_code.is_success() {
            let did_document: DidDocument = serde_json::from_str(&response.body)?;
            Ok(did_document)
        } else {
            Err(DidWebvhIdentifierError::DidWebvhRequestFailed(
                response.body,
            ))
        }
    }

    async fn update_identifier(
        &self,
        _path: &str,
        _keyring: KeyPairing,
    ) -> Result<DidDocument, Self::DidWebvhIdentifierError> {
        unimplemented!()
    }

    async fn deactivate_identifier(
        &self,
        _path: &str,
        _keyring: KeyPairing,
    ) -> Result<DidDocument, Self::DidWebvhIdentifierError> {
        unimplemented!()
    }
}
