use crate::services::{
    internal::did_vc::DIDVCService, nodex::NodeX, project_verifier::ProjectVerifier,
};
use anyhow::Context;
use chrono::DateTime;
use chrono::Utc;

use serde::{Deserialize, Serialize};
use serde_json::Value;
use uuid::Uuid;

#[async_trait::async_trait]
pub trait DidRepository {
    async fn find_identifier(&self, did: &str) -> anyhow::Result<()>;
}

pub struct DidRepositoryImpl {}

impl DidRepositoryImpl {
    pub fn new() -> Self {
        Self {}
    }
}

#[async_trait::async_trait]
impl DidRepository for DidRepositoryImpl {
    async fn find_identifier(&self, did: &str) -> anyhow::Result<()> {
        let service = NodeX::new();

        service
            .find_identifier(did)
            .await
            .context("destination did not found")?;

        Ok(())
    }
}

pub struct VerifiableMessageUseCase {
    project_verifier: Box<dyn ProjectVerifier>,
    did_repository: Box<dyn DidRepository>,
}

impl VerifiableMessageUseCase {
    pub fn new(
        project_verifier: Box<dyn ProjectVerifier>,
        did_repository: Box<dyn DidRepository>,
    ) -> Self {
        Self {
            project_verifier,
            did_repository,
        }
    }
}

impl VerifiableMessageUseCase {
    pub async fn generate(
        &self,
        destination_did: String,
        message: String,
        now: DateTime<Utc>,
    ) -> anyhow::Result<String> {
        self.did_repository
            .find_identifier(&destination_did)
            .await?;

        let message = EncodedMessage {
            message_id: Uuid::new_v4().to_string(),
            payload: message,
            destination_did: destination_did.clone(),
            created_at: now.to_rfc3339(),
            project_hmac: self.project_verifier.create_project_hmac()?,
        };

        let message = serde_json::to_value(message)?;
        let vc = DIDVCService::generate(&message, now)?;

        Ok(serde_json::to_string(&vc)?)
    }

    #[allow(dead_code)]
    pub async fn verify(&self, message: &str) -> anyhow::Result<String> {
        let message = serde_json::from_str::<Value>(message)?;

        println!("message: {:?}", message);
        let vc = DIDVCService::verify(&message)
            .await
            .context("verify failed")?;
        println!("vc: {:?}", vc);

        let container = vc
            .get("credentialSubject")
            .context("credentialSubject not found")?
            .get("container")
            .context("container not found")?
            .clone();

        let message = serde_json::from_value::<EncodedMessage>(container)?;

        if !self
            .project_verifier
            .verify_project_hmac(&message.project_hmac)?
        {
            anyhow::bail!("project hmac is not valid");
        }

        Ok(message.payload)
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct EncodedMessage {
    pub message_id: String,
    pub payload: String,
    pub destination_did: String,
    pub created_at: String,
    pub project_hmac: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::services::project_verifier::ProjectVerifier;

    struct MockProjectVerifier {}

    impl ProjectVerifier for MockProjectVerifier {
        fn create_project_hmac(&self) -> anyhow::Result<String> {
            Ok("mock".to_string())
        }

        fn verify_project_hmac(&self, _signature: &str) -> anyhow::Result<bool> {
            Ok(true)
        }
    }

    struct MockDidRepository {}

    #[async_trait::async_trait]
    impl DidRepository for MockDidRepository {
        async fn find_identifier(&self, _did: &str) -> anyhow::Result<()> {
            Ok(())
        }
    }

    #[tokio::test]
    async fn test_verifiable_message_usecase() {
        // generate local did and keys
        // NOTE: this is integration test
        // TODO: use mock or move to integration test
        NodeX::new().create_identifier().await.unwrap();

        let usecase = VerifiableMessageUseCase {
            project_verifier: Box::new(MockProjectVerifier {}),
            did_repository: Box::new(MockDidRepository {}),
        };

        let destination_did = "did:example:123".to_string();
        let message = "Hello".to_string();

        let now = Utc::now();
        let generated = usecase
            .generate(destination_did, message.clone(), now)
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
                "destination_did": "did:example:123",
                "created_at": now.to_rfc3339(),
                "project_hmac": "mock"
            })
        );

        let verified = usecase.verify(&generated).await.unwrap();
        assert_eq!(verified, message);
    }
}
