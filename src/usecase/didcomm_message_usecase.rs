use anyhow::Context;
use chrono::{DateTime, Utc};

use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;
use uuid::Uuid;

use crate::{
    nodex::schema::general::GeneralVcDataModel,
    repository::message_activity_repository::{
        CreatedMessageActivityRequest, MessageActivityRepository, VerifiedMessageActivityRequest,
        VerifiedStatus,
    },
    services::{internal::didcomm_encrypted::*, project_verifier::ProjectVerifier},
};

pub struct DidcommMessageUseCase {
    project_verifier: Box<dyn ProjectVerifier + Send + Sync + 'static>,
    message_activity_repository: Box<dyn MessageActivityRepository + Send + Sync + 'static>,
    didcomm_encrypted_service: DIDCommEncryptedService,
}

impl DidcommMessageUseCase {
    pub fn new<
        V: ProjectVerifier + Send + Sync + 'static,
        R: MessageActivityRepository + Send + Sync + 'static,
    >(
        project_verifier: V,
        message_activity_repository: R,
        didcomm_encrypted_service: DIDCommEncryptedService,
    ) -> DidcommMessageUseCase {
        DidcommMessageUseCase {
            project_verifier: Box::new(project_verifier),
            message_activity_repository: Box::new(message_activity_repository),
            didcomm_encrypted_service,
        }
    }
}

#[derive(Debug, Error)]
pub enum GenerateDidcommMessageUseCaseError {
    #[error("target did not found : {0}")]
    TargetDidNotFound(String),
    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

#[derive(Debug, Error)]
pub enum VerifyDidcommMessageUseCaseError {
    #[error("verification failed")]
    VerificationFailed,
    #[error("target did not found : {0}")]
    TargetDidNotFound(String),
    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

impl DidcommMessageUseCase {
    pub async fn generate(
        &self,
        destination_did: String,
        message: String,
        operation_tag: String,
        now: DateTime<Utc>,
    ) -> Result<String, GenerateDidcommMessageUseCaseError> {
        let message_id = Uuid::new_v4();
        let my_did = super::get_my_did();

        let message = EncodedMessage {
            message_id,
            payload: message,
            created_at: now.to_rfc3339(),
            project_hmac: self.project_verifier.create_project_hmac()?,
        };
        let message = serde_json::to_value(message).context("failed to convert to value")?;

        let didcomm_message = self
            .didcomm_encrypted_service
            .generate(&destination_did, &message, None, now)
            .await
            .map_err(|e| match e {
                DIDCommEncryptedServiceError::DIDNotFound(d) => {
                    GenerateDidcommMessageUseCaseError::TargetDidNotFound(d)
                }
                _ => GenerateDidcommMessageUseCaseError::Other(e.into()),
            })?;

        let result = serde_json::to_string(&didcomm_message).context("failed to serialize")?;

        self.message_activity_repository
            .add_create_activity(CreatedMessageActivityRequest {
                message_id,
                from: my_did,
                to: destination_did,
                operation_tag,
                is_encrypted: true,
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
    ) -> Result<GeneralVcDataModel, VerifyDidcommMessageUseCaseError> {
        let message = serde_json::from_str::<Value>(message).context("failed to decode str")?;
        let verified = self
            .didcomm_encrypted_service
            .verify(&message)
            .await
            .map_err(|e| {
                dbg!(&e);
                match e {
                    DIDCommEncryptedServiceError::DIDNotFound(d) => {
                        VerifyDidcommMessageUseCaseError::TargetDidNotFound(d)
                    }
                    _ => VerifyDidcommMessageUseCaseError::Other(e.into()),
                }
            })?;
        // metadata field is not used
        let verified = verified.message;

        let from_did = verified.issuer.id.clone();
        // check in verified. maybe exists?
        let my_did = super::get_my_did();

        let container = verified.clone().credential_subject.container;

        let message = serde_json::from_value::<EncodedMessage>(container)
            .context("failed to deserialize to EncodedMessage")?;

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
            Ok(verified)
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
            Err(VerifyDidcommMessageUseCaseError::VerificationFailed)
        }
    }
}

#[derive(Serialize, Deserialize, Debug)]
struct EncodedMessage {
    pub message_id: Uuid,
    pub payload: String,
    pub created_at: String,
    pub project_hmac: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::repository::did_repository::DidRepository as _;
    use crate::usecase::get_my_did;
    use crate::{
        nodex::sidetree::payload::DIDResolutionResponse,
        services::project_verifier::ProjectVerifier,
    };
    use crate::{
        services::internal::did_vc::DIDVCService,
        usecase::{
            didcomm_message_usecase::DidcommMessageUseCase, verifiable_message_usecase::tests::*,
        },
    };
    use serde_json;

    #[tokio::test]
    async fn test_create_and_verify() {
        // generate local did and keys
        let repository = MockDidRepository {};
        let _did = repository.create_identifier().await.unwrap();
        dbg!(&_did);

        let usecase = DidcommMessageUseCase::new(
            MockProjectVerifier {},
            MockActivityRepository {},
            DIDCommEncryptedService::new(
                MockDidRepository {},
                DIDVCService::new(MockDidRepository {}),
            ),
        );

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

        let verified = usecase.verify(&generated, Utc::now()).await.unwrap();
        let encoded_message =
            serde_json::from_value::<EncodedMessage>(verified.credential_subject.container)
                .unwrap();
        assert_eq!(encoded_message.payload, message);
    }

    mod generate_failed {
        use super::*;
        use crate::repository::did_repository::DidRepository;

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

            let usecase = DidcommMessageUseCase::new(
                MockProjectVerifier {},
                MockActivityRepository {},
                DIDCommEncryptedService::new(
                    NotFoundDidRepository {},
                    DIDVCService::new(MockDidRepository {}),
                ),
            );

            let destination_did = "did:example:123".to_string();
            let message = "Hello".to_string();

            let now = Utc::now();
            let generated = usecase
                .generate(destination_did, message, "test".to_string(), now)
                .await;

            if let Err(GenerateDidcommMessageUseCaseError::TargetDidNotFound(_)) = generated {
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

            let usecase = DidcommMessageUseCase::new(
                CreateProjectHmacFailedVerifier {},
                MockActivityRepository {},
                DIDCommEncryptedService::new(
                    MockDidRepository {},
                    DIDVCService::new(MockDidRepository {}),
                ),
            );

            let destination_did = "did:example:123".to_string();
            let message = "Hello".to_string();

            let now = Utc::now();
            let generated = usecase
                .generate(destination_did, message, "test".to_string(), now)
                .await;

            if let Err(GenerateDidcommMessageUseCaseError::Other(_)) = generated {
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

            let usecase = DidcommMessageUseCase::new(
                MockProjectVerifier {},
                CreateActivityFailedRepository {},
                DIDCommEncryptedService::new(
                    MockDidRepository {},
                    DIDVCService::new(MockDidRepository {}),
                ),
            );

            let destination_did = "did:example:123".to_string();
            let message = "Hello".to_string();

            let now = Utc::now();
            let generated = usecase
                .generate(destination_did, message, "test".to_string(), now)
                .await;

            if let Err(GenerateDidcommMessageUseCaseError::Other(_)) = generated {
            } else {
                panic!("unexpected result: {:?}", generated);
            }
        }
    }

    mod verify_failed {
        use super::*;
        use crate::repository::did_repository::DidRepository;

        async fn create_test_message_for_verify_test() -> String {
            let usecase = DidcommMessageUseCase::new(
                MockProjectVerifier {},
                MockActivityRepository {},
                DIDCommEncryptedService::new(
                    MockDidRepository {},
                    DIDVCService::new(MockDidRepository {}),
                ),
            );

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

            generated
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

            let usecase = DidcommMessageUseCase::new(
                MockProjectVerifier {},
                MockActivityRepository {},
                DIDCommEncryptedService::new(
                    NotFoundDidRepository {},
                    DIDVCService::new(MockDidRepository {}),
                ),
            );

            let generated = create_test_message_for_verify_test().await;
            let verified = usecase.verify(&generated, Utc::now()).await;

            if let Err(VerifyDidcommMessageUseCaseError::TargetDidNotFound(_)) = verified {
            } else {
                panic!("unexpected result: {:#?}", verified);
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

            let usecase = DidcommMessageUseCase::new(
                MockProjectVerifier {},
                VerifyActivityFailedRepository {},
                DIDCommEncryptedService::new(
                    MockDidRepository {},
                    DIDVCService::new(MockDidRepository {}),
                ),
            );

            let generated = create_test_message_for_verify_test().await;
            let verified = usecase.verify(&generated, Utc::now()).await;

            if let Err(VerifyDidcommMessageUseCaseError::Other(_)) = verified {
            } else {
                panic!("unexpected result: {:?}", verified);
            }
        }
    }
}
