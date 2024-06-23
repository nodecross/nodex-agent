use crate::nodex::utils::did_accessor::DIDAccessor;
use crate::{
    repository::message_activity_repository::*, services::project_verifier::ProjectVerifier,
};
use anyhow::Context;
use chrono::DateTime;
use chrono::Utc;
use nodex_didcomm::{
    did::did_repository::DidRepository,
    verifiable_credentials::{
        did_vc::{DIDVCService, DIDVCServiceGenerateError, DIDVCServiceVerifyError},
        types::VerifiableCredentials,
    },
};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;

pub struct VerifiableMessageUseCase<D: DidRepository> {
    project_verifier: Box<dyn ProjectVerifier>,
    did_repository: Box<dyn DidRepository>,
    message_activity_repository: Box<dyn MessageActivityRepository>,
    vc_service: DIDVCService<D>,
    did_accessor: Box<dyn DIDAccessor>,
}

impl<D: DidRepository> VerifiableMessageUseCase<D> {
    pub fn new(
        project_verifier: Box<dyn ProjectVerifier>,
        did_repository: Box<dyn DidRepository>,
        message_activity_repository: Box<dyn MessageActivityRepository>,
        vc_service: DIDVCService<D>,
        did_accessor: Box<dyn DIDAccessor>,
    ) -> Self {
        Self {
            project_verifier,
            did_repository,
            message_activity_repository,
            vc_service,
            did_accessor,
        }
    }
}

#[derive(Debug, Error)]
pub enum CreateVerifiableMessageUseCaseError {
    #[error("destination did not found")]
    DestinationNotFound,
    #[error(transparent)]
    VCServiceFailed(#[from] DIDVCServiceGenerateError),
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
pub enum VerifyVerifiableMessageUseCaseError {
    #[error("verification failed")]
    VerificationFailed,
    #[error("This message is not addressed to me")]
    NotAddressedToMe,
    #[error(transparent)]
    VCServiceFailed(#[from] DIDVCServiceVerifyError),
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

impl<D: DidRepository> VerifiableMessageUseCase<D> {
    pub async fn generate(
        &self,
        destination_did: String,
        message: String,
        operation_tag: String,
        now: DateTime<Utc>,
    ) -> Result<String, CreateVerifiableMessageUseCaseError> {
        self.did_repository
            .find_identifier(&destination_did)
            .await
            .context("unexpected error occurred when find a did")?
            .ok_or(CreateVerifiableMessageUseCaseError::DestinationNotFound)?;

        let message_id = Uuid::new_v4();
        let my_did = self.did_accessor.get_my_did();
        let message = EncodedMessage {
            message_id,
            payload: message,
            destination_did: destination_did.clone(),
            created_at: now.to_rfc3339(),
            project_hmac: self.project_verifier.create_project_hmac()?,
        };

        let message = serde_json::to_value(message).context("failed to convert to value")?;
        let vc = self.vc_service.generate(
            &my_did,
            &self.did_accessor.get_my_keyring(),
            &message,
            now,
        )?;

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
            .map_err(|e| match e {
                MessageActivityHttpError::BadRequest(message) => {
                    CreateVerifiableMessageUseCaseError::BadRequest(message)
                }
                MessageActivityHttpError::Unauthorized(message) => {
                    CreateVerifiableMessageUseCaseError::Unauthorized(message)
                }
                MessageActivityHttpError::Forbidden(message) => {
                    CreateVerifiableMessageUseCaseError::Forbidden(message)
                }
                MessageActivityHttpError::NotFound(message) => {
                    CreateVerifiableMessageUseCaseError::NotFound(message)
                }
                MessageActivityHttpError::Conflict(message) => {
                    CreateVerifiableMessageUseCaseError::Conflict(message)
                }
                _ => CreateVerifiableMessageUseCaseError::Other(e.into()),
            })?;

        // Discard the unused result
        let _ = result;

        Ok(result)
    }

    pub async fn verify(
        &self,
        message: &str,
        now: DateTime<Utc>,
    ) -> Result<VerifiableCredentials, VerifyVerifiableMessageUseCaseError> {
        let vc = serde_json::from_str::<VerifiableCredentials>(message)
            .context("failed to decode str")?;
        let vc = self.vc_service.verify(vc).await?;
        let container = vc.clone().credential_subject.container;

        let message = serde_json::from_value::<EncodedMessage>(container)
            .context("failed to deserialize to EncodedMessage")?;

        let from_did = vc.issuer.id.clone();
        let my_did = self.did_accessor.get_my_did();

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
                .map_err(|e| match e {
                    MessageActivityHttpError::BadRequest(message) => {
                        VerifyVerifiableMessageUseCaseError::BadRequest(message)
                    }
                    MessageActivityHttpError::Unauthorized(message) => {
                        VerifyVerifiableMessageUseCaseError::Unauthorized(message)
                    }
                    MessageActivityHttpError::Forbidden(message) => {
                        VerifyVerifiableMessageUseCaseError::Forbidden(message)
                    }
                    MessageActivityHttpError::NotFound(message) => {
                        VerifyVerifiableMessageUseCaseError::NotFound(message)
                    }
                    MessageActivityHttpError::Conflict(message) => {
                        VerifyVerifiableMessageUseCaseError::Conflict(message)
                    }
                    _ => VerifyVerifiableMessageUseCaseError::Other(e.into()),
                })?;
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
                .map_err(|e| match e {
                    MessageActivityHttpError::BadRequest(message) => {
                        VerifyVerifiableMessageUseCaseError::BadRequest(message)
                    }
                    MessageActivityHttpError::Unauthorized(message) => {
                        VerifyVerifiableMessageUseCaseError::Unauthorized(message)
                    }
                    MessageActivityHttpError::Forbidden(message) => {
                        VerifyVerifiableMessageUseCaseError::Forbidden(message)
                    }
                    MessageActivityHttpError::NotFound(message) => {
                        VerifyVerifiableMessageUseCaseError::NotFound(message)
                    }
                    MessageActivityHttpError::Conflict(message) => {
                        VerifyVerifiableMessageUseCaseError::Conflict(message)
                    }
                    _ => VerifyVerifiableMessageUseCaseError::Other(e.into()),
                })?;
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
    use crate::nodex::utils::did_accessor::mocks::MockDIDAccessor;
    use crate::repository::did_repository::mocks::MockDidRepository;
    use crate::services::project_verifier::mocks::MockProjectVerifier;

    use crate::usecase::test_util::*;
    use nodex_didcomm::verifiable_credentials::did_vc::DIDVCService;
    use serde_json::Value;
    use tests::mocks::MockMessageActivityRepository;

    #[tokio::test]
    async fn test_create_and_verify() {
        let presets = TestPresets::default();
        let repository = presets.create_mock_did_repository();

        let usecase = VerifiableMessageUseCase {
            project_verifier: Box::new(MockProjectVerifier::create_success()),
            did_repository: Box::new(repository.clone()),
            message_activity_repository: Box::new(MockMessageActivityRepository::create_success()),
            vc_service: DIDVCService::new(repository.clone()),
            did_accessor: Box::new(MockDIDAccessor::new(presets.from_did, presets.from_keyring)),
        };

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

        let result: Value = serde_json::from_str(&generated).unwrap();

        let message_id = result["credentialSubject"]["container"]["message_id"]
            .as_str()
            .unwrap();

        assert_eq!(
            result["credentialSubject"]["container"],
            serde_json::json!({
                "message_id": message_id,
                "payload": "Hello",
                "destination_did": &presets.to_did,
                "created_at": now.to_rfc3339(),
                "project_hmac": "mock"
            })
        );

        let usecase = VerifiableMessageUseCase {
            project_verifier: Box::new(MockProjectVerifier::verify_success()),
            did_repository: Box::new(repository.clone()),
            message_activity_repository: Box::new(MockMessageActivityRepository::verify_success()),
            vc_service: DIDVCService::new(repository.clone()),
            did_accessor: Box::new(MockDIDAccessor::new(presets.to_did, presets.to_keyring)),
        };

        let verified = usecase.verify(&generated, Utc::now()).await.unwrap();
        let encoded_message =
            serde_json::from_value::<EncodedMessage>(verified.credential_subject.container)
                .unwrap();
        assert_eq!(encoded_message.payload, message);
    }

    mod generate_failed {
        use crate::nodex::utils::did_accessor::mocks::MockDIDAccessor;

        use super::*;

        #[tokio::test]
        async fn test_generate_did_not_found() {
            let presets = TestPresets::default();
            let repository = presets.create_mock_did_repository();

            let usecase = VerifiableMessageUseCase {
                project_verifier: Box::new(MockProjectVerifier::create_success()),
                did_repository: Box::new(MockDidRepository::empty()),
                message_activity_repository: Box::new(
                    MockMessageActivityRepository::create_success(),
                ),
                vc_service: DIDVCService::new(repository.clone()),
                did_accessor: Box::new(MockDIDAccessor::new(
                    presets.from_did,
                    presets.from_keyring,
                )),
            };

            let message = "Hello".to_string();

            let now = Utc::now();
            let generated = usecase
                .generate(presets.to_did, message, "test".to_string(), now)
                .await;

            if let Err(CreateVerifiableMessageUseCaseError::DestinationNotFound) = generated {
            } else {
                panic!("unexpected result: {:?}", generated);
            }
        }

        #[tokio::test]
        async fn test_generate_create_project_hmac_failed() {
            let presets = TestPresets::default();
            let repository = presets.create_mock_did_repository();

            let usecase = VerifiableMessageUseCase {
                project_verifier: Box::new(MockProjectVerifier::create_failed()),
                did_repository: Box::new(repository.clone()),
                message_activity_repository: Box::new(
                    MockMessageActivityRepository::create_success(),
                ),
                vc_service: DIDVCService::new(repository),
                did_accessor: Box::new(MockDIDAccessor::new(
                    presets.from_did,
                    presets.from_keyring,
                )),
            };

            let message = "Hello".to_string();

            let now = Utc::now();
            let generated = usecase
                .generate(presets.to_did, message, "test".to_string(), now)
                .await;

            if let Err(CreateVerifiableMessageUseCaseError::Other(_)) = generated {
            } else {
                panic!("unexpected result: {:?}", generated);
            }
        }

        #[tokio::test]
        async fn test_generate_add_activity_failed() {
            let presets = TestPresets::default();
            let repository = presets.create_mock_did_repository();

            let usecase = VerifiableMessageUseCase {
                project_verifier: Box::new(MockProjectVerifier::create_success()),
                did_repository: Box::new(repository.clone()),
                message_activity_repository: Box::new(MockMessageActivityRepository::create_fail()),
                vc_service: DIDVCService::new(repository),
                did_accessor: Box::new(MockDIDAccessor::new(
                    presets.from_did,
                    presets.from_keyring,
                )),
            };

            let message = "Hello".to_string();

            let now = Utc::now();
            let generated = usecase
                .generate(presets.to_did, message, "test".to_string(), now)
                .await;

            if let Err(CreateVerifiableMessageUseCaseError::Other(_)) = generated {
            } else {
                panic!("unexpected result: {:?}", generated);
            }
        }
    }

    mod verify_failed {
        use crate::nodex::utils::did_accessor::mocks::MockDIDAccessor;

        use super::*;

        async fn create_test_message_for_verify_test(presets: TestPresets) -> String {
            let repository = presets.create_mock_did_repository();

            let usecase = VerifiableMessageUseCase {
                project_verifier: Box::new(MockProjectVerifier::create_success()),
                did_repository: Box::new(repository.clone()),
                message_activity_repository: Box::new(
                    MockMessageActivityRepository::create_success(),
                ),
                vc_service: DIDVCService::new(repository),
                did_accessor: Box::new(MockDIDAccessor::new(
                    presets.from_did,
                    presets.from_keyring,
                )),
            };

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

            let result: Value = serde_json::from_str(&generated).unwrap();

            let message_id = result["credentialSubject"]["container"]["message_id"]
                .as_str()
                .unwrap();

            assert_eq!(
                result["credentialSubject"]["container"],
                serde_json::json!({
                    "message_id": message_id,
                    "payload": "Hello",
                    "destination_did": &presets.to_did,
                    "created_at": now.to_rfc3339(),
                    "project_hmac": "mock"
                })
            );

            generated
        }

        #[tokio::test]
        async fn test_verify_not_addressed_to_me() {
            let presets = TestPresets::default();
            let repository = presets.create_mock_did_repository();

            let generated = create_test_message_for_verify_test(presets.clone()).await;

            let _message = "Hello".to_string();

            let usecase = VerifiableMessageUseCase {
                project_verifier: Box::new(MockProjectVerifier::verify_success()),
                did_repository: Box::new(repository.clone()),
                message_activity_repository: Box::new(
                    MockMessageActivityRepository::verify_success(),
                ),
                vc_service: DIDVCService::new(repository.clone()),
                did_accessor: Box::new(MockDIDAccessor::new(
                    "wrong_did".to_owned(),
                    presets.to_keyring,
                )),
            };

            let verified = usecase.verify(&generated, Utc::now()).await;

            if let Err(VerifyVerifiableMessageUseCaseError::NotAddressedToMe) = verified {
            } else {
                panic!("unexpected result: {:?}", verified);
            }
        }

        #[tokio::test]
        async fn test_verify_verify_failed() {
            let presets = TestPresets::default();
            let repository = presets.create_mock_did_repository();

            let generated = create_test_message_for_verify_test(presets.clone()).await;

            let usecase = VerifiableMessageUseCase {
                project_verifier: Box::new(MockProjectVerifier::verify_failed()),
                did_repository: Box::new(repository.clone()),
                message_activity_repository: Box::new(
                    MockMessageActivityRepository::verify_success(),
                ),
                vc_service: DIDVCService::new(repository.clone()),
                did_accessor: Box::new(MockDIDAccessor::new(presets.to_did, presets.to_keyring)),
            };

            let verified = usecase.verify(&generated, Utc::now()).await;

            if let Err(VerifyVerifiableMessageUseCaseError::VerificationFailed) = verified {
            } else {
                panic!("unexpected result: {:?}", verified);
            }
        }

        #[tokio::test]
        async fn test_verify_verify_error_throwed() {
            let presets = TestPresets::default();
            let repository = presets.create_mock_did_repository();

            let generated = create_test_message_for_verify_test(presets.clone()).await;

            let usecase = VerifiableMessageUseCase {
                project_verifier: Box::new(MockProjectVerifier::verify_throw_error()),
                did_repository: Box::new(repository.clone()),
                message_activity_repository: Box::new(
                    MockMessageActivityRepository::verify_success(),
                ),
                vc_service: DIDVCService::new(repository.clone()),
                did_accessor: Box::new(MockDIDAccessor::new(presets.to_did, presets.to_keyring)),
            };

            let verified = usecase.verify(&generated, Utc::now()).await;

            if let Err(VerifyVerifiableMessageUseCaseError::Other(_)) = verified {
            } else {
                panic!("unexpected result: {:?}", verified);
            }
        }

        #[tokio::test]
        async fn test_verify_did_not_found() {
            let presets = TestPresets::default();

            let repository = MockDidRepository::empty();

            let usecase = VerifiableMessageUseCase {
                project_verifier: Box::new(MockProjectVerifier::verify_success()),
                did_repository: Box::new(repository.clone()),
                message_activity_repository: Box::new(
                    MockMessageActivityRepository::verify_success(),
                ),
                vc_service: DIDVCService::new(repository),
                did_accessor: Box::new(MockDIDAccessor::new(
                    presets.clone().to_did,
                    presets.clone().to_keyring,
                )),
            };

            let generated = create_test_message_for_verify_test(presets).await;
            let verified = usecase.verify(&generated, Utc::now()).await;

            if let Err(VerifyVerifiableMessageUseCaseError::VCServiceFailed(
                DIDVCServiceVerifyError::DIDNotFound(_),
            )) = verified
            {
            } else {
                panic!("unexpected result: {:?}", verified);
            }
        }

        #[tokio::test]
        async fn test_verify_add_activity_failed() {
            let presets = TestPresets::default();
            let repository = presets.create_mock_did_repository();

            let generated = create_test_message_for_verify_test(presets.clone()).await;

            let usecase = VerifiableMessageUseCase {
                project_verifier: Box::new(MockProjectVerifier::verify_success()),
                did_repository: Box::new(repository.clone()),
                message_activity_repository: Box::new(MockMessageActivityRepository::verify_fail()),
                vc_service: DIDVCService::new(repository.clone()),
                did_accessor: Box::new(MockDIDAccessor::new(presets.to_did, presets.to_keyring)),
            };

            let verified = usecase.verify(&generated, Utc::now()).await;

            if let Err(VerifyVerifiableMessageUseCaseError::Other(_)) = verified {
            } else {
                panic!("unexpected result: {:?}", verified);
            }
        }
    }
}
