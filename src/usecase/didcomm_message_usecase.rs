use anyhow::Context;
use chrono::{DateTime, Utc};

use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;

use crate::{
    nodex::utils::did_accessor::DIDAccessor,
    repository::message_activity_repository::{
        CreatedMessageActivityRequest, MessageActivityHttpError, MessageActivityRepository,
        VerifiedMessageActivityRequest, VerifiedStatus,
    },
    services::project_verifier::ProjectVerifier,
};
use nodex_didcomm::{
    did::did_repository::DidRepository,
    didcomm::{
        encrypted::{
            DIDCommEncryptedService, DIDCommEncryptedServiceGenerateError,
            DIDCommEncryptedServiceVerifyError,
        },
        types::DIDCommMessage,
    },
    verifiable_credentials::types::VerifiableCredentials,
};

pub struct DidcommMessageUseCase<D: DidRepository> {
    project_verifier: Box<dyn ProjectVerifier + Send + Sync + 'static>,
    message_activity_repository: Box<dyn MessageActivityRepository + Send + Sync + 'static>,
    didcomm_encrypted_service: DIDCommEncryptedService<D>,
    did_accessor: Box<dyn DIDAccessor + Send + Sync + 'static>,
}

impl<D: DidRepository> DidcommMessageUseCase<D> {
    pub fn new<
        V: ProjectVerifier + Send + Sync + 'static,
        R: MessageActivityRepository + Send + Sync + 'static,
        A: DIDAccessor + Send + Sync + 'static,
    >(
        project_verifier: V,
        message_activity_repository: R,
        didcomm_encrypted_service: DIDCommEncryptedService<D>,
        did_accessor: A,
    ) -> DidcommMessageUseCase<D> {
        DidcommMessageUseCase {
            project_verifier: Box::new(project_verifier),
            message_activity_repository: Box::new(message_activity_repository),
            didcomm_encrypted_service,
            did_accessor: Box::new(did_accessor),
        }
    }
}

#[derive(Debug, Error)]
pub enum GenerateDidcommMessageUseCaseError {
    #[error("target did not found : {0}")]
    TargetDidNotFound(String),
    #[error("bad request: {0}")]
    BadRequest(String),
    #[error("unauthorized: {0}")]
    Unauthorized(String),
    #[error("forbidden: {0}")]
    Forbidden(String),
    #[error("not found: {0}")]
    NotFound(String),
    #[error("conflict: {0}")]
    Conflict(String),
    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

#[derive(Debug, Error)]
pub enum VerifyDidcommMessageUseCaseError {
    #[error("verification failed")]
    VerificationFailed,
    #[error("target did not found : {0}")]
    TargetDidNotFound(String),
    #[error("bad request: {0}")]
    BadRequest(String),
    #[error("unauthorized: {0}")]
    Unauthorized(String),
    #[error("forbidden: {0}")]
    Forbidden(String),
    #[error("not found: {0}")]
    NotFound(String),
    #[error("conflict: {0}")]
    Conflict(String),
    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

impl<D: DidRepository> DidcommMessageUseCase<D> {
    pub async fn generate(
        &self,
        destination_did: String,
        message: String,
        operation_tag: String,
        now: DateTime<Utc>,
    ) -> Result<String, GenerateDidcommMessageUseCaseError> {
        let message_id = Uuid::new_v4();

        let message = EncodedMessage {
            message_id,
            payload: message,
            created_at: now.to_rfc3339(),
            project_hmac: self.project_verifier.create_project_hmac()?,
        };
        let message = serde_json::to_value(message).context("failed to convert to value")?;
        let my_did = self.did_accessor.get_my_did();
        let didcomm_message = self
            .didcomm_encrypted_service
            .generate(
                &self.did_accessor.get_my_did(),
                &destination_did,
                &self.did_accessor.get_my_keyring(),
                &message,
                None,
                now,
            )
            .await
            .map_err(|e| match e {
                DIDCommEncryptedServiceGenerateError::DIDNotFound(d) => {
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
            .map_err(|e| match e {
                MessageActivityHttpError::BadRequest(message) => {
                    GenerateDidcommMessageUseCaseError::BadRequest(message)
                }
                MessageActivityHttpError::Unauthorized(message) => {
                    GenerateDidcommMessageUseCaseError::Unauthorized(message)
                }
                MessageActivityHttpError::Forbidden(message) => {
                    GenerateDidcommMessageUseCaseError::Forbidden(message)
                }
                MessageActivityHttpError::NotFound(message) => {
                    GenerateDidcommMessageUseCaseError::NotFound(message)
                }
                MessageActivityHttpError::Conflict(message) => {
                    GenerateDidcommMessageUseCaseError::Conflict(message)
                }
                _ => GenerateDidcommMessageUseCaseError::Other(e.into()),
            })?;

        // Discard the unused result
        let _ = result;

        Ok(result)
    }

    pub async fn verify(
        &self,
        message: &str,
        now: DateTime<Utc>,
    ) -> Result<VerifiableCredentials, VerifyDidcommMessageUseCaseError> {
        let message =
            serde_json::from_str::<DIDCommMessage>(message).context("failed to decode str")?;
        let verified = self
            .didcomm_encrypted_service
            .verify(&self.did_accessor.get_my_keyring(), &message)
            .await
            .map_err(|e| {
                log::debug!("{}", &e);
                match e {
                    DIDCommEncryptedServiceVerifyError::DIDNotFound(d) => {
                        VerifyDidcommMessageUseCaseError::TargetDidNotFound(d)
                    }
                    _ => VerifyDidcommMessageUseCaseError::Other(e.into()),
                }
            })?;
        // metadata field is not used
        let verified = verified.message;

        let from_did = verified.issuer.id.clone();
        // check in verified. maybe exists?
        let my_did = self.did_accessor.get_my_did();

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
                .map_err(|e| match e {
                    MessageActivityHttpError::BadRequest(message) => {
                        VerifyDidcommMessageUseCaseError::BadRequest(message)
                    }
                    MessageActivityHttpError::Unauthorized(message) => {
                        VerifyDidcommMessageUseCaseError::Unauthorized(message)
                    }
                    MessageActivityHttpError::Forbidden(message) => {
                        VerifyDidcommMessageUseCaseError::Forbidden(message)
                    }
                    MessageActivityHttpError::NotFound(message) => {
                        VerifyDidcommMessageUseCaseError::NotFound(message)
                    }
                    MessageActivityHttpError::Conflict(message) => {
                        VerifyDidcommMessageUseCaseError::Conflict(message)
                    }
                    _ => VerifyDidcommMessageUseCaseError::Other(e.into()),
                })?;
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
                .map_err(|e| match e {
                    MessageActivityHttpError::BadRequest(message) => {
                        VerifyDidcommMessageUseCaseError::BadRequest(message)
                    }
                    MessageActivityHttpError::Unauthorized(message) => {
                        VerifyDidcommMessageUseCaseError::Unauthorized(message)
                    }
                    MessageActivityHttpError::Forbidden(message) => {
                        VerifyDidcommMessageUseCaseError::Forbidden(message)
                    }
                    MessageActivityHttpError::NotFound(message) => {
                        VerifyDidcommMessageUseCaseError::NotFound(message)
                    }
                    MessageActivityHttpError::Conflict(message) => {
                        VerifyDidcommMessageUseCaseError::Conflict(message)
                    }
                    _ => VerifyDidcommMessageUseCaseError::Other(e.into()),
                })?;
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
    use crate::nodex::utils::did_accessor::mocks::MockDIDAccessor;
    use crate::repository::did_repository::mocks::MockDidRepository;
    use crate::repository::message_activity_repository::mocks::MockMessageActivityRepository;
    use crate::services::project_verifier::mocks::MockProjectVerifier;

    use crate::usecase::didcomm_message_usecase::DidcommMessageUseCase;
    use crate::usecase::test_util::TestPresets;
    use nodex_didcomm::didcomm::encrypted::DIDCommEncryptedService;

    use serde_json;

    #[tokio::test]
    async fn test_create_and_verify() {
        let presets = TestPresets::default();

        let service = DIDCommEncryptedService::new(presets.create_mock_did_repository(), None);

        let usecase = DidcommMessageUseCase::new(
            MockProjectVerifier::create_success(),
            MockMessageActivityRepository::create_success(),
            service.clone(),
            MockDIDAccessor::new(presets.from_did, presets.from_keyring),
        );

        let message = "Hello".to_string();

        let now = Utc::now();
        let generated = usecase
            .generate(
                presets.to_did.clone(),
                message.clone(),
                "test".to_string(),
                now,
            )
            .await
            .unwrap();

        let usecase = DidcommMessageUseCase::new(
            MockProjectVerifier::verify_success(),
            MockMessageActivityRepository::verify_success(),
            service,
            MockDIDAccessor::new(presets.to_did, presets.to_keyring),
        );

        let verified = usecase.verify(&generated, Utc::now()).await.unwrap();
        let encoded_message =
            serde_json::from_value::<EncodedMessage>(verified.credential_subject.container)
                .unwrap();
        assert_eq!(encoded_message.payload, message);
    }

    mod generate_failed {
        use crate::{
            nodex::utils::did_accessor::mocks::MockDIDAccessor,
            services::project_verifier::mocks::MockProjectVerifier,
        };

        use super::*;

        #[tokio::test]
        async fn test_generate_did_not_found() {
            let presets = TestPresets::default();

            let usecase = DidcommMessageUseCase::new(
                MockProjectVerifier::create_success(),
                MockMessageActivityRepository::create_success(),
                DIDCommEncryptedService::new(MockDidRepository::empty(), None),
                MockDIDAccessor::new(presets.from_did, presets.from_keyring),
            );

            let message = "Hello".to_string();

            let now = Utc::now();
            let generated = usecase
                .generate(presets.to_did.clone(), message, "test".to_string(), now)
                .await;

            if let Err(GenerateDidcommMessageUseCaseError::TargetDidNotFound(_)) = generated {
            } else {
                panic!("unexpected result: {:?}", generated);
            }
        }

        #[tokio::test]
        async fn test_generate_create_project_hmac_failed() {
            let presets = TestPresets::default();

            let usecase = DidcommMessageUseCase::new(
                MockProjectVerifier::create_failed(),
                MockMessageActivityRepository::create_success(),
                DIDCommEncryptedService::new(presets.create_mock_did_repository(), None),
                MockDIDAccessor::new(presets.from_did, presets.from_keyring),
            );

            let message = "Hello".to_string();

            let now = Utc::now();
            let generated = usecase
                .generate(presets.to_did.clone(), message, "test".to_string(), now)
                .await;

            if let Err(GenerateDidcommMessageUseCaseError::Other(_)) = generated {
            } else {
                panic!("unexpected result: {:?}", generated);
            }
        }

        #[tokio::test]
        async fn test_generate_add_activity_failed() {
            let presets = TestPresets::default();

            let usecase = DidcommMessageUseCase::new(
                MockProjectVerifier::create_success(),
                MockMessageActivityRepository::create_fail(),
                DIDCommEncryptedService::new(presets.create_mock_did_repository(), None),
                MockDIDAccessor::new(presets.from_did, presets.from_keyring),
            );

            let message = "Hello".to_string();

            let now = Utc::now();
            let generated = usecase
                .generate(presets.to_did.clone(), message, "test".to_string(), now)
                .await;

            if let Err(GenerateDidcommMessageUseCaseError::Other(_)) = generated {
            } else {
                panic!("unexpected result: {:?}", generated);
            }
        }
    }

    mod verify_failed {
        use super::*;
        use crate::{
            nodex::utils::did_accessor::mocks::MockDIDAccessor,
            services::project_verifier::mocks::MockProjectVerifier,
        };

        async fn create_test_message_for_verify_test(presets: TestPresets) -> String {
            let usecase = DidcommMessageUseCase::new(
                MockProjectVerifier::create_success(),
                MockMessageActivityRepository::create_success(),
                DIDCommEncryptedService::new(presets.create_mock_did_repository(), None),
                MockDIDAccessor::new(presets.from_did, presets.from_keyring),
            );

            let message = "Hello".to_string();

            let now = Utc::now();

            usecase
                .generate(
                    presets.to_did.clone(),
                    message.clone(),
                    "test".to_string(),
                    now,
                )
                .await
                .unwrap()
        }

        #[tokio::test]
        async fn test_verify_did_not_found() {
            let presets = TestPresets::default();
            let generated = create_test_message_for_verify_test(presets.clone()).await;

            let usecase = DidcommMessageUseCase::new(
                MockProjectVerifier::verify_success(),
                MockMessageActivityRepository::verify_success(),
                DIDCommEncryptedService::new(MockDidRepository::empty(), None),
                MockDIDAccessor::new(presets.to_did, presets.to_keyring),
            );

            let verified = usecase.verify(&generated, Utc::now()).await;

            if let Err(VerifyDidcommMessageUseCaseError::TargetDidNotFound(_)) = verified {
            } else {
                panic!("unexpected result: {:#?}", verified);
            }
        }

        #[tokio::test]
        async fn test_verify_add_activity_failed() {
            let presets = TestPresets::default();
            let generated = create_test_message_for_verify_test(presets.clone()).await;

            let usecase = DidcommMessageUseCase::new(
                MockProjectVerifier::verify_success(),
                MockMessageActivityRepository::verify_fail(),
                DIDCommEncryptedService::new(presets.create_mock_did_repository(), None),
                MockDIDAccessor::new(presets.from_did, presets.from_keyring),
            );

            let verified = usecase.verify(&generated, Utc::now()).await;

            if let Err(VerifyDidcommMessageUseCaseError::Other(_)) = verified {
            } else {
                panic!("unexpected result: {:?}", verified);
            }
        }
    }
}
