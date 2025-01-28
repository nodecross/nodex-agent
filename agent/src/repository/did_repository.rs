#[cfg(test)]
pub mod mocks {
    use protocol::{
        did::{
            did_repository::{CreateIdentifierError, DidRepository, FindIdentifierError},
            sidetree::payload::{DidDocument, DidPublicKey, DidResolutionResponse, MethodMetadata},
        },
        keyring::jwk::Jwk,
        keyring::keypair::{KeyPair, KeyPairing},
    };
    use std::{collections::BTreeMap, convert::TryFrom};

    #[derive(Clone)]
    pub struct MockDidRepository {
        map: BTreeMap<String, Vec<KeyPairing>>,
    }

    impl MockDidRepository {
        pub fn from_pairs(map: impl IntoIterator<Item = (String, KeyPairing)>) -> Self {
            Self {
                map: map.into_iter().map(|(k, v)| (k, vec![v])).collect(),
            }
        }

        pub fn empty() -> Self {
            Self {
                map: BTreeMap::new(),
            }
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
                                public_key_jwk: Jwk::try_from(&keyring.sign.get_public_key())
                                    .unwrap(),
                            },
                            DidPublicKey {
                                id: "#encryptionKey".to_string(),
                                controller: String::new(),
                                r#type: "X25519KeyAgreementKey2019".to_string(),
                                public_key_jwk: Jwk::from(&keyring.encrypt.get_public_key()),
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
