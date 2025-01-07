use super::sidetree::{
    client::SidetreeHttpClient,
    payload::{
        did_create_payload, DidDocument, DidPatchDocument, DidResolutionResponse, ToPublicKey,
    },
};
use crate::keyring::keypair::{KeyPair, KeyPairing};
use http::StatusCode;
use std::convert::TryInto;

#[derive(Debug, thiserror::Error)]
pub enum CreateIdentifierError<StudioClientError: std::error::Error> {
    #[error("Failed to convert to JWK: {0}")]
    Jwk(#[from] crate::keyring::jwk::K256ToJwkError),
    #[error("Failed to build operation payload: {0}")]
    PayloadBuildFailed(#[from] crate::did::sidetree::payload::DidCreatePayloadError),
    #[error("Failed to parse body: {0}")]
    BodyParse(#[from] serde_json::Error),
    #[error("Failed to create identifier. response: {0}")]
    SidetreeRequestFailed(String),
    #[error("Failed to send request: {0}")]
    SidetreeHttpClient(StudioClientError),
}

#[derive(Debug, thiserror::Error)]
pub enum FindIdentifierError<StudioClientError: std::error::Error> {
    #[error("Failed to send request to sidetree: {0}")]
    SidetreeRequestFailed(String),
    #[error("Failed to parse body: {0}")]
    BodyParse(#[from] serde_json::Error),
    #[error("Failed to send request: {0}")]
    SidetreeHttpClient(StudioClientError),
}

#[derive(Debug, thiserror::Error)]
pub enum GetPublicKeyError {
    #[error("Failed to get public key: {0}")]
    PublicKeyNotFound(String),
    #[error("Failed to convert from JWK: {0}")]
    JwkToK256(#[from] crate::keyring::jwk::JwkToK256Error),
    #[error("Failed to convert from JWK: {0}")]
    JwkToX25519(#[from] crate::keyring::jwk::JwkToX25519Error),
}

pub fn get_sign_key(did_document: &DidDocument) -> Result<k256::PublicKey, GetPublicKeyError> {
    let did = &did_document.id;
    let public_key = did_document
        .get_key("#signingKey")
        .ok_or_else(|| GetPublicKeyError::PublicKeyNotFound(did.to_string()))?;
    Ok(public_key.try_into()?)
}

pub fn get_encrypt_key(
    did_document: &DidDocument,
) -> Result<x25519_dalek::PublicKey, GetPublicKeyError> {
    let did = &did_document.id;
    let public_key = did_document
        .get_key("#encryptionKey")
        .ok_or_else(|| GetPublicKeyError::PublicKeyNotFound(did.to_string()))?;
    Ok(public_key.try_into()?)
}

#[trait_variant::make(Send)]
pub trait DidRepository: Sync {
    type CreateIdentifierError: std::error::Error + Send + Sync;
    type FindIdentifierError: std::error::Error + Send + Sync;
    async fn create_identifier(
        &self,
        keyring: KeyPairing,
    ) -> Result<DidResolutionResponse, Self::CreateIdentifierError>;
    async fn find_identifier(
        &self,
        did: &str,
    ) -> Result<Option<DidResolutionResponse>, Self::FindIdentifierError>;
}

#[derive(Clone)]
pub struct DidRepositoryImpl<C: SidetreeHttpClient> {
    client: C,
}

impl<C: SidetreeHttpClient> DidRepositoryImpl<C> {
    pub fn new(client: C) -> Self {
        Self { client }
    }
}

impl<C> DidRepository for DidRepositoryImpl<C>
where
    C: SidetreeHttpClient + Send + Sync,
    C::Error: Send + Sync,
{
    type CreateIdentifierError = CreateIdentifierError<C::Error>;
    type FindIdentifierError = FindIdentifierError<C::Error>;
    async fn create_identifier(
        &self,
        keyring: KeyPairing,
    ) -> Result<DidResolutionResponse, CreateIdentifierError<C::Error>> {
        // https://w3c.github.io/did-spec-registries/#assertionmethod
        // FIXME: This purpose property is strange...
        //        I guess the sidetree protocol this impl uses is too old.
        // https://identity.foundation/sidetree/spec/#add-public-keys
        // vec!["assertionMethod".to_string()],
        let sign = keyring.sign.get_public_key().to_public_key(
            "EcdsaSecp256k1VerificationKey2019".to_string(),
            "signingKey".to_string(),
            vec!["auth".to_string(), "general".to_string()],
        )?;
        // vec!["keyAgreement".to_string()]
        let enc = keyring
            .encrypt
            .get_public_key()
            .to_public_key(
                "X25519KeyAgreementKey2019".to_string(),
                "encryptionKey".to_string(),
                vec!["auth".to_string(), "general".to_string()],
            )
            .unwrap();
        let update = keyring.update.get_public_key();
        let recovery = keyring.recovery.get_public_key();
        let document = DidPatchDocument {
            public_keys: vec![sign, enc],
            service_endpoints: vec![],
        };
        let payload = did_create_payload(document, update, recovery)?;

        let response = self
            .client
            .post_create_identifier(&payload)
            .await
            .map_err(CreateIdentifierError::SidetreeHttpClient)?;
        if response.status_code.is_success() {
            Ok(serde_json::from_str(&response.body)?)
        } else {
            Err(CreateIdentifierError::SidetreeRequestFailed(format!(
                "{:?}",
                response
            )))
        }
    }

    async fn find_identifier(
        &self,
        did: &str,
    ) -> Result<Option<DidResolutionResponse>, FindIdentifierError<C::Error>> {
        let response = self
            .client
            .get_find_identifier(did)
            .await
            .map_err(FindIdentifierError::SidetreeHttpClient)?;

        match response.status_code {
            StatusCode::OK => Ok(Some(serde_json::from_str(&response.body)?)),
            StatusCode::NOT_FOUND => Ok(None),
            _ => Err(FindIdentifierError::SidetreeRequestFailed(format!(
                "{:?}",
                response
            ))),
        }
    }
}

#[cfg(test)]
pub mod mocks {
    use std::collections::BTreeMap;

    use super::*;
    use crate::{
        did::sidetree::payload::{DidDocument, DidPublicKey, MethodMetadata},
        keyring::keypair::KeyPairing,
    };

    #[derive(Clone)]
    pub struct MockDidRepository {
        map: BTreeMap<String, Vec<KeyPairing>>,
    }

    impl MockDidRepository {
        pub fn from_single(map: BTreeMap<String, KeyPairing>) -> Self {
            Self {
                map: map.into_iter().map(|(k, v)| (k, vec![v])).collect(),
            }
        }

        pub fn new(map: BTreeMap<String, Vec<KeyPairing>>) -> Self {
            Self { map }
        }
    }

    #[derive(Debug, thiserror::Error)]
    pub enum DummyError {}

    impl DidRepository for MockDidRepository {
        type CreateIdentifierError = CreateIdentifierError<DummyError>;
        type FindIdentifierError = FindIdentifierError<DummyError>;
        async fn create_identifier(
            &self,
            _keyring: KeyPairing,
        ) -> Result<DidResolutionResponse, Self::CreateIdentifierError> {
            unimplemented!()
        }
        async fn find_identifier(
            &self,
            did: &str,
        ) -> Result<Option<DidResolutionResponse>, Self::FindIdentifierError> {
            if let Some(keyrings) = self.map.get(did) {
                let public_keys = keyrings
                    .iter()
                    .flat_map(|keyring| {
                        vec![
                            DidPublicKey {
                                id: "#signingKey".to_string(),
                                controller: String::new(),
                                r#type: "EcdsaSecp256k1VerificationKey2019".to_string(),
                                public_key_jwk: (&keyring.sign.get_public_key()).try_into().unwrap(),
                            },
                            DidPublicKey {
                                id: "#encryptionKey".to_string(),
                                controller: String::new(),
                                r#type: "X25519KeyAgreementKey2019".to_string(),
                                public_key_jwk: (&keyring.encrypt.get_public_key()).into(),
                            },
                        ]
                    })
                    .collect();

                let response = DidResolutionResponse {
                    context: "https://www.w3.org/ns/did-resolution/v1".to_string(),
                    did_document: DidDocument {
                        id: did.to_string(),
                        public_key: Some(public_keys),
                        service: None,
                        authentication: Some(vec!["signingKey".to_string()]),
                    },
                    method_metadata: MethodMetadata {
                        published: true,
                        recovery_commitment: None,
                        update_commitment: None,
                    },
                };
                Ok(Some(response))
            } else {
                Ok(None)
            }
        }
    }

    #[derive(Clone, Copy)]
    pub struct NoPublicKeyDidRepository;

    impl DidRepository for NoPublicKeyDidRepository {
        type CreateIdentifierError = CreateIdentifierError<DummyError>;
        type FindIdentifierError = FindIdentifierError<DummyError>;
        async fn create_identifier(
            &self,
            _keyring: KeyPairing,
        ) -> Result<DidResolutionResponse, Self::CreateIdentifierError> {
            unimplemented!()
        }
        async fn find_identifier(
            &self,
            did: &str,
        ) -> Result<Option<DidResolutionResponse>, Self::FindIdentifierError> {
            Ok(Some(DidResolutionResponse {
                context: "https://www.w3.org/ns/did-resolution/v1".to_string(),
                did_document: DidDocument {
                    id: did.to_string(),
                    public_key: None,
                    service: None,
                    authentication: None,
                },
                method_metadata: MethodMetadata {
                    published: true,
                    recovery_commitment: None,
                    update_commitment: None,
                },
            }))
        }
    }

    #[derive(Clone, Copy)]
    pub struct IllegalPublicKeyLengthDidRepository;

    impl DidRepository for IllegalPublicKeyLengthDidRepository {
        type CreateIdentifierError = CreateIdentifierError<DummyError>;
        type FindIdentifierError = FindIdentifierError<DummyError>;
        async fn create_identifier(
            &self,
            _keyring: KeyPairing,
        ) -> Result<DidResolutionResponse, Self::CreateIdentifierError> {
            unimplemented!()
        }
        async fn find_identifier(
            &self,
            did: &str,
        ) -> Result<Option<DidResolutionResponse>, Self::FindIdentifierError> {
            Ok(Some(DidResolutionResponse {
                context: "https://www.w3.org/ns/did-resolution/v1".to_string(),
                did_document: DidDocument {
                    id: did.to_string(),
                    public_key: Some(vec![]),
                    service: None,
                    authentication: None,
                },
                method_metadata: MethodMetadata {
                    published: true,
                    recovery_commitment: None,
                    update_commitment: None,
                },
            }))
        }
    }
}
