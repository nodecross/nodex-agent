use crate::{
    nodex::schema::general::GeneralVcDataModel,
    repository::{did_repository::DidRepository, message_activity_repository::*},
    services::{
        internal::did_vc::{DIDVCService, DIDVCServiceError},
        project_verifier::ProjectVerifier,
    },
};
use anyhow::Context;
use chrono::DateTime;
use chrono::Utc;
use serde::{Deserialize, Serialize};

use thiserror::Error;
use uuid::Uuid;

pub struct VerifiableMessageUseCase {
    project_verifier: Box<dyn ProjectVerifier>,
    did_repository: Box<dyn DidRepository>,
    message_activity_repository: Box<dyn MessageActivityRepository>,
    vc_service: DIDVCService,
}

impl VerifiableMessageUseCase {
    pub fn new(
        project_verifier: Box<dyn ProjectVerifier>,
        did_repository: Box<dyn DidRepository>,
        message_activity_repository: Box<dyn MessageActivityRepository>,
        vc_service: DIDVCService,
    ) -> Self {
        Self {
            project_verifier,
            did_repository,
            message_activity_repository,
            vc_service,
        }
    }
}

#[derive(Debug, Error)]
pub enum CreateVerifiableMessageUseCaseError {
    #[error("destination did not found")]
    DestinationNotFound,
    #[error(transparent)]
    VCServiceFailed(#[from] DIDVCServiceError),
    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

#[derive(Debug, Error)]
pub enum VerifyVerifiableMessageUseCaseError {
    #[error("verification failed")]
    VerificationFailed,
    #[error("This message is not addressed to me")]
    NotAddressedToMe,
    #[error(transparent)]
    VCServiceFailed(#[from] DIDVCServiceError),
    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

impl VerifiableMessageUseCase {
    pub async fn generate(
        &self,
        destination_did: String,
        message: String,
        operation_tag: String,
        now: DateTime<Utc>,
    ) -> Result<String, CreateVerifiableMessageUseCaseError> {
        self.did_repository
            .find_identifier(&destination_did)
            .await?
            .ok_or(CreateVerifiableMessageUseCaseError::DestinationNotFound)?;

        let message_id = Uuid::new_v4();
        let my_did = super::get_my_did();
        let message = EncodedMessage {
            message_id,
            payload: message,
            destination_did: destination_did.clone(),
            created_at: now.to_rfc3339(),
            project_hmac: self.project_verifier.create_project_hmac()?,
        };

        let message = serde_json::to_value(message).context("failed to convert to value")?;
        let vc = DIDVCService::generate(&self.vc_service, &message, now)?;

        let result = serde_json::to_string(&vc).context("failed to serialize")?;

        self.message_activity_repository
            .add_create_activity(CreatedMessageActivityRequest {
                message_id,
                from: my_did,
                to: destination_did,
                operation_tag,
                is_encrypted: false,
                occurred_at: now,
            })
            .await
            .context("failed to add create activity")?;

        Ok(result)
    }

    pub async fn verify(
        &self,
        message: &str,
        now: DateTime<Utc>,
    ) -> Result<GeneralVcDataModel, VerifyVerifiableMessageUseCaseError> {
        let vc =
            serde_json::from_str::<GeneralVcDataModel>(message).context("failed to decode str")?;
        let from_did = vc.issuer.id.clone();

        // TODO: return GeneralVCDataModel
        let _ = DIDVCService::verify(&self.vc_service, vc.clone())
            .await
            .context("verify failed")?;

        let container = vc.clone().credential_subject.container;

        let message = serde_json::from_value::<EncodedMessage>(container)
            .context("failed to deserialize to EncodedMessage")?;

        let my_did = super::get_my_did();

        if message.destination_did != my_did {
            return Err(VerifyVerifiableMessageUseCaseError::NotAddressedToMe);
        }

        if self
            .project_verifier
            .verify_project_hmac(&message.project_hmac)?
        {
            self.message_activity_repository
                .add_verify_activity(VerifiedMessageActivityRequest {
                    from: from_did,
                    to: my_did,
                    message_id: message.message_id,
                    verified_at: now,
                    status: VerifiedStatus::Valid,
                })
                .await
                .context("failed to add verify activity")?;
            Ok(vc)
        } else {
            self.message_activity_repository
                .add_verify_activity(VerifiedMessageActivityRequest {
                    from: from_did,
                    to: my_did,
                    message_id: message.message_id,
                    verified_at: now,
                    status: VerifiedStatus::Invalid,
                })
                .await
                .context("failed to add verify activity")?;
            Err(VerifyVerifiableMessageUseCaseError::VerificationFailed)
        }
    }
}

#[derive(Serialize, Deserialize, Debug)]
struct EncodedMessage {
    pub message_id: Uuid,
    pub payload: String,
    pub destination_did: String,
    pub created_at: String,
    pub project_hmac: String,
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::usecase::get_my_did;
    use crate::{
        nodex::keyring::keypair::KeyPairing,
        nodex::sidetree::payload::{
            DIDDocument, DIDResolutionResponse, DidPublicKey, MethodMetadata,
        },
        services::project_verifier::ProjectVerifier,
    };
    use serde_json::Value;

    pub struct MockProjectVerifier {}

    impl ProjectVerifier for MockProjectVerifier {
        fn create_project_hmac(&self) -> anyhow::Result<String> {
            Ok("mock".to_string())
        }

        fn verify_project_hmac(&self, _signature: &str) -> anyhow::Result<bool> {
            Ok(true)
        }
    }

    pub struct MockDidRepository {}

    const DEFAULT_DID: &str = "did:nodex:test:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

    #[async_trait::async_trait]
    impl DidRepository for MockDidRepository {
        async fn create_identifier(&self) -> anyhow::Result<DIDResolutionResponse> {
            if KeyPairing::load_keyring().is_err() {
                // DID doesn't matter
                let mut keyring = KeyPairing::create_keyring()?;
                keyring.save(DEFAULT_DID);
            }

            self.find_identifier(DEFAULT_DID)
                .await
                .and_then(|x| x.context("unreachable"))
        }
        async fn find_identifier(
            &self,
            did: &str,
        ) -> anyhow::Result<Option<DIDResolutionResponse>> {
            // extract from NodeX::create_identifier
            let jwk = KeyPairing::load_keyring()?
                .get_sign_key_pair()
                .to_jwk(false)?;

            let response = DIDResolutionResponse {
                context: "https://www.w3.org/ns/did-resolution/v1".to_string(),
                did_document: DIDDocument {
                    id: did.to_string(),
                    public_key: Some(vec![DidPublicKey {
                        id: did.to_string() + "#signingKey",
                        controller: String::new(),
                        r#type: "EcdsaSecp256k1VerificationKey2019".to_string(),
                        public_key_jwk: jwk,
                    }]),
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
        }
    }

    pub struct MockActivityRepository {}

    #[async_trait::async_trait]
    impl MessageActivityRepository for MockActivityRepository {
        async fn add_create_activity(
            &self,
            _request: CreatedMessageActivityRequest,
        ) -> anyhow::Result<()> {
            Ok(())
        }

        async fn add_verify_activity(
            &self,
            _request: VerifiedMessageActivityRequest,
        ) -> anyhow::Result<()> {
            Ok(())
        }
    }

    #[tokio::test]
    async fn test_create_and_verify() {
        // generate local did and keys
        let repository = MockDidRepository {};
        let _did = repository.create_identifier().await.unwrap();
        dbg!(&_did);

        let usecase = VerifiableMessageUseCase {
            project_verifier: Box::new(MockProjectVerifier {}),
            did_repository: Box::new(MockDidRepository {}),
            message_activity_repository: Box::new(MockActivityRepository {}),
            vc_service: DIDVCService::new(MockDidRepository {}),
        };

        let destination_did = get_my_did();
        let message = "Hello".to_string();

        let now = Utc::now();
        let generated = usecase
            .generate(
                destination_did.clone(),
                message.clone(),
                "test".to_string(),
                now,
            )
            .await
            .unwrap();

        let result: Value = serde_json::from_str(&generated).unwrap();
        dbg!(&result);

        let message_id = result["credentialSubject"]["container"]["message_id"]
            .as_str()
            .unwrap();

        assert_eq!(
            result["credentialSubject"]["container"],
            serde_json::json!({
                "message_id": message_id,
                "payload": "Hello",
                "destination_did": destination_did,
                "created_at": now.to_rfc3339(),
                "project_hmac": "mock"
            })
        );

        let verified = usecase.verify(&generated, Utc::now()).await.unwrap();
        assert_eq!(verified, message);
    }

    mod generate_failed {
        use super::*;

        #[tokio::test]
        async fn test_generate_did_not_found() {
            struct NotFoundDidRepository {}

            #[async_trait::async_trait]
            impl DidRepository for NotFoundDidRepository {
                async fn create_identifier(&self) -> anyhow::Result<DIDResolutionResponse> {
                    unreachable!()
                }
                async fn find_identifier(
                    &self,
                    _did: &str,
                ) -> anyhow::Result<Option<DIDResolutionResponse>> {
                    Ok(None)
                }
            }

            let usecase = VerifiableMessageUseCase {
                project_verifier: Box::new(MockProjectVerifier {}),
                did_repository: Box::new(NotFoundDidRepository {}),
                message_activity_repository: Box::new(MockActivityRepository {}),
                vc_service: DIDVCService::new(MockDidRepository {}),
            };

            let destination_did = "did:example:123".to_string();
            let message = "Hello".to_string();

            let now = Utc::now();
            let generated = usecase
                .generate(destination_did, message, "test".to_string(), now)
                .await;

            if let Err(CreateVerifiableMessageUseCaseError::DestinationNotFound) = generated {
            } else {
                panic!("unexpected result: {:?}", generated);
            }
        }

        #[tokio::test]
        async fn test_generate_create_project_hmac_failed() {
            struct CreateProjectHmacFailedVerifier {}

            impl ProjectVerifier for CreateProjectHmacFailedVerifier {
                fn create_project_hmac(&self) -> anyhow::Result<String> {
                    Err(anyhow::anyhow!("create project hmac failed"))
                }
                fn verify_project_hmac(&self, _signature: &str) -> anyhow::Result<bool> {
                    unreachable!()
                }
            }

            let usecase = VerifiableMessageUseCase {
                project_verifier: Box::new(CreateProjectHmacFailedVerifier {}),
                did_repository: Box::new(MockDidRepository {}),
                message_activity_repository: Box::new(MockActivityRepository {}),
                vc_service: DIDVCService::new(MockDidRepository {}),
            };

            let destination_did = "did:example:123".to_string();
            let message = "Hello".to_string();

            let now = Utc::now();
            let generated = usecase
                .generate(destination_did, message, "test".to_string(), now)
                .await;

            if let Err(CreateVerifiableMessageUseCaseError::Other(_)) = generated {
            } else {
                panic!("unexpected result: {:?}", generated);
            }
        }

        #[tokio::test]
        async fn test_generate_add_activity_failed() {
            struct CreateActivityFailedRepository {}

            #[async_trait::async_trait]
            impl MessageActivityRepository for CreateActivityFailedRepository {
                async fn add_create_activity(
                    &self,
                    _request: CreatedMessageActivityRequest,
                ) -> anyhow::Result<()> {
                    Err(anyhow::anyhow!("create activity failed"))
                }

                async fn add_verify_activity(
                    &self,
                    _request: VerifiedMessageActivityRequest,
                ) -> anyhow::Result<()> {
                    unreachable!()
                }
            }

            let usecase = VerifiableMessageUseCase {
                project_verifier: Box::new(MockProjectVerifier {}),
                did_repository: Box::new(MockDidRepository {}),
                message_activity_repository: Box::new(CreateActivityFailedRepository {}),
                vc_service: DIDVCService::new(MockDidRepository {}),
            };

            let destination_did = "did:example:123".to_string();
            let message = "Hello".to_string();

            let now = Utc::now();
            let generated = usecase
                .generate(destination_did, message, "test".to_string(), now)
                .await;

            if let Err(CreateVerifiableMessageUseCaseError::Other(_)) = generated {
            } else {
                panic!("unexpected result: {:?}", generated);
            }
        }
    }

    mod verify_failed {
        use super::*;

        async fn create_test_message_for_verify_test() -> String {
            let usecase = VerifiableMessageUseCase {
                project_verifier: Box::new(MockProjectVerifier {}),
                did_repository: Box::new(MockDidRepository {}),
                message_activity_repository: Box::new(MockActivityRepository {}),
                vc_service: DIDVCService::new(MockDidRepository {}),
            };

            let destination_did = get_my_did();
            let message = "Hello".to_string();

            let now = Utc::now();
            let generated = usecase
                .generate(
                    destination_did.clone(),
                    message.clone(),
                    "test".to_string(),
                    now,
                )
                .await
                .unwrap();

            let result: Value = serde_json::from_str(&generated).unwrap();

            let message_id = result["credentialSubject"]["container"]["message_id"]
                .as_str()
                .unwrap();

            assert_eq!(
                result["credentialSubject"]["container"],
                serde_json::json!({
                    "message_id": message_id,
                    "payload": "Hello",
                    "destination_did": destination_did,
                    "created_at": now.to_rfc3339(),
                    "project_hmac": "mock"
                })
            );

            generated
        }

        #[tokio::test]
        async fn test_verify_not_addressed_to_me() {
            // generate local did and keys
            let repository = MockDidRepository {};
            repository.create_identifier().await.unwrap();

            let destination_did = "did:nodex:test:ILLEGAL".to_string();
            let message = "Hello".to_string();

            let usecase = VerifiableMessageUseCase {
                project_verifier: Box::new(MockProjectVerifier {}),
                did_repository: Box::new(MockDidRepository {}),
                message_activity_repository: Box::new(MockActivityRepository {}),
                vc_service: DIDVCService::new(MockDidRepository {}),
            };

            let now = Utc::now();
            let generated = usecase
                .generate(destination_did, message.clone(), "test".to_string(), now)
                .await
                .unwrap();

            let verified = usecase.verify(&generated, Utc::now()).await;

            if let Err(VerifyVerifiableMessageUseCaseError::NotAddressedToMe) = verified {
            } else {
                panic!("unexpected result: {:?}", verified);
            }
        }

        #[tokio::test]
        async fn test_verify_verify_failed() {
            // generate local did and keys
            let repository = MockDidRepository {};
            repository.create_identifier().await.unwrap();

            struct VerifyFailedVerifier {}

            impl ProjectVerifier for VerifyFailedVerifier {
                fn create_project_hmac(&self) -> anyhow::Result<String> {
                    Ok("mock".to_string())
                }
                fn verify_project_hmac(&self, _signature: &str) -> anyhow::Result<bool> {
                    Ok(false)
                }
            }

            let usecase = VerifiableMessageUseCase {
                project_verifier: Box::new(VerifyFailedVerifier {}),
                did_repository: Box::new(MockDidRepository {}),
                message_activity_repository: Box::new(MockActivityRepository {}),
                vc_service: DIDVCService::new(MockDidRepository {}),
            };

            let generated = create_test_message_for_verify_test().await;
            let verified = usecase.verify(&generated, Utc::now()).await;

            if let Err(VerifyVerifiableMessageUseCaseError::VerificationFailed) = verified {
            } else {
                panic!("unexpected result: {:?}", verified);
            }
        }

        #[tokio::test]
        async fn test_verify_did_not_found() {
            // generate local did and keys
            let repository = MockDidRepository {};
            repository.create_identifier().await.unwrap();

            struct NotFoundDidRepository {}

            #[async_trait::async_trait]
            impl DidRepository for NotFoundDidRepository {
                async fn create_identifier(&self) -> anyhow::Result<DIDResolutionResponse> {
                    unreachable!()
                }
                async fn find_identifier(
                    &self,
                    _did: &str,
                ) -> anyhow::Result<Option<DIDResolutionResponse>> {
                    Ok(None)
                }
            }

            let usecase = VerifiableMessageUseCase {
                project_verifier: Box::new(MockProjectVerifier {}),
                did_repository: Box::new(MockDidRepository {}),
                message_activity_repository: Box::new(MockActivityRepository {}),
                vc_service: DIDVCService::new(NotFoundDidRepository {}),
            };

            let generated = create_test_message_for_verify_test().await;
            let verified = usecase.verify(&generated, Utc::now()).await;

            if let Err(VerifyVerifiableMessageUseCaseError::Other(_)) = verified {
            } else {
                panic!("unexpected result: {:?}", verified);
            }
        }

        #[tokio::test]
        async fn test_verify_add_activity_failed() {
            struct VerifyActivityFailedRepository {}

            #[async_trait::async_trait]
            impl MessageActivityRepository for VerifyActivityFailedRepository {
                async fn add_create_activity(
                    &self,
                    _request: CreatedMessageActivityRequest,
                ) -> anyhow::Result<()> {
                    unreachable!()
                }

                async fn add_verify_activity(
                    &self,
                    _request: VerifiedMessageActivityRequest,
                ) -> anyhow::Result<()> {
                    Err(anyhow::anyhow!("verify activity failed"))
                }
            }

            let usecase = VerifiableMessageUseCase {
                project_verifier: Box::new(MockProjectVerifier {}),
                did_repository: Box::new(MockDidRepository {}),
                message_activity_repository: Box::new(VerifyActivityFailedRepository {}),
                vc_service: DIDVCService::new(MockDidRepository {}),
            };

            let generated = create_test_message_for_verify_test().await;
            let verified = usecase.verify(&generated, Utc::now()).await;

            if let Err(VerifyVerifiableMessageUseCaseError::Other(_)) = verified {
            } else {
                panic!("unexpected result: {:?}", verified);
            }
        }
    }
}
