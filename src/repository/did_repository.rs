#[cfg(test)]
pub mod mocks {
    use std::collections::BTreeMap;

    use nodex_didcomm::{
        did::{
            did_repository::{CreateIdentifierError, DidRepository, FindIdentifierError},
            sidetree::payload::{DIDDocument, DIDResolutionResponse, DidPublicKey, MethodMetadata},
        },
        keyring::keypair::KeyPairing,
    };

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

    #[async_trait::async_trait]
    impl DidRepository for MockDidRepository {
        async fn create_identifier(
            &self,
            _keyring: KeyPairing,
        ) -> Result<DIDResolutionResponse, CreateIdentifierError> {
            unimplemented!()
        }
        async fn find_identifier(
            &self,
            did: &str,
        ) -> Result<Option<DIDResolutionResponse>, FindIdentifierError> {
            if let Some(keyrings) = self.map.get(did) {
                let public_keys = keyrings
                    .iter()
                    .map(|keyring| DidPublicKey {
                        id: did.to_string() + "#signingKey",
                        controller: String::new(),
                        r#type: "EcdsaSecp256k1VerificationKey2019".to_string(),
                        public_key_jwk: keyring.sign.to_jwk(false).unwrap(),
                    })
                    .collect();

                let response = DIDResolutionResponse {
                    context: "https://www.w3.org/ns/did-resolution/v1".to_string(),
                    did_document: DIDDocument {
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

    #[async_trait::async_trait]
    impl DidRepository for NoPublicKeyDidRepository {
        async fn create_identifier(
            &self,
            _keyring: KeyPairing,
        ) -> Result<DIDResolutionResponse, CreateIdentifierError> {
            unimplemented!()
        }
        async fn find_identifier(
            &self,
            did: &str,
        ) -> Result<Option<DIDResolutionResponse>, FindIdentifierError> {
            Ok(Some(DIDResolutionResponse {
                context: "https://www.w3.org/ns/did-resolution/v1".to_string(),
                did_document: DIDDocument {
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

    #[async_trait::async_trait]
    impl DidRepository for IllegalPublicKeyLengthDidRepository {
        async fn create_identifier(
            &self,
            _keyring: KeyPairing,
        ) -> Result<DIDResolutionResponse, CreateIdentifierError> {
            unimplemented!()
        }
        async fn find_identifier(
            &self,
            did: &str,
        ) -> Result<Option<DIDResolutionResponse>, FindIdentifierError> {
            Ok(Some(DIDResolutionResponse {
                context: "https://www.w3.org/ns/did-resolution/v1".to_string(),
                did_document: DIDDocument {
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
