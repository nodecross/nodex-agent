use hmac::{Hmac, Mac};

use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

pub trait ProjectVerifier {
    fn create_project_hmac(&self) -> anyhow::Result<String>;
    fn verify_project_hmac(&self, signature: &str) -> anyhow::Result<bool>;
}

pub struct ProjectVerifierImplOnNetworkConfig {}

impl ProjectVerifierImplOnNetworkConfig {
    pub fn new() -> Self {
        ProjectVerifierImplOnNetworkConfig {}
    }
}

impl ProjectVerifier for ProjectVerifierImplOnNetworkConfig {
    fn create_project_hmac(&self) -> anyhow::Result<String> {
        let network = crate::network_config();
        let network = network.lock();
        let project_did = network
            .get_project_did()
            .ok_or(anyhow::anyhow!("project_did is not set"))?;
        let secret_key = network
            .get_secret_key()
            .ok_or(anyhow::anyhow!("secret key is not set"))?;

        let mut hmac = HmacSha256::new_from_slice(secret_key.as_bytes())?;
        hmac.update(project_did.as_bytes());

        let signature = hex::encode(hmac.finalize().into_bytes());

        Ok(signature)
    }

    fn verify_project_hmac(&self, signature: &str) -> anyhow::Result<bool> {
        let signature = hex::decode(signature)?;
        let network = crate::network_config();
        let network = network.lock();
        let project_did = network
            .get_project_did()
            .ok_or(anyhow::anyhow!("project_did is not set"))?;
        let secret_key = network
            .get_secret_key()
            .ok_or(anyhow::anyhow!("secret key is not set"))?;

        let mut hmac = HmacSha256::new_from_slice(secret_key.as_bytes())?;
        hmac.update(project_did.as_bytes());

        Ok(hmac.verify_slice(&signature).is_ok())
    }
}

#[cfg(test)]
pub mod mocks {
    use super::*;

    pub struct MockProjectVerifier {
        create: Option<bool>,
        verify: Option<Option<bool>>,
    }

    impl MockProjectVerifier {
        pub fn create_success() -> Self {
            MockProjectVerifier {
                create: Some(true),
                verify: None,
            }
        }

        pub fn create_failed() -> Self {
            MockProjectVerifier {
                create: Some(false),
                verify: None,
            }
        }

        pub fn verify_success() -> Self {
            MockProjectVerifier {
                create: None,
                verify: Some(Some(true)),
            }
        }

        pub fn verify_failed() -> Self {
            MockProjectVerifier {
                create: None,
                verify: Some(Some(false)),
            }
        }

        pub fn verify_throw_error() -> Self {
            MockProjectVerifier {
                create: None,
                verify: Some(None),
            }
        }
    }

    impl ProjectVerifier for MockProjectVerifier {
        fn create_project_hmac(&self) -> anyhow::Result<String> {
            let create = self.create.expect("this method should not be called");
            if create {
                Ok("mock".to_string())
            } else {
                Err(anyhow::anyhow!("create failed"))
            }
        }

        fn verify_project_hmac(&self, _signature: &str) -> anyhow::Result<bool> {
            let verify = self.verify.expect("this method should not be called");
            match verify {
                Some(result) => Ok(result),
                None => Err(anyhow::anyhow!("verify failed")),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::network_config;

    fn initialize_network_config() {
        // NOTE: don't write operation in test functions to avoid deadlock

        let network = network_config();
        let mut network = network.lock();
        if network.get_project_did().is_none() {
            network.save_project_did("project_did");
        }
        if network.get_secret_key().is_none() {
            network.save_secret_key("secret_key");
        }
    }

    #[test]
    fn test_create_project_hmac_impl() {
        initialize_network_config();

        let project_verifier = ProjectVerifierImplOnNetworkConfig::new();
        let result = project_verifier.create_project_hmac();
        assert!(result.is_ok());
        let result = result.unwrap();
        let result = project_verifier.verify_project_hmac(&result).unwrap();
        assert_eq!(result, true);
    }
}
