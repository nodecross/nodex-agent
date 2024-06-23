pub mod didcomm_message_usecase;
pub mod metric_usecase;
pub mod verifiable_message_usecase;

#[cfg(test)]
mod test_util {
    use nodex_didcomm::keyring::{extension::trng::OSRandomNumberGenerator, keypair::KeyPairing};

    use crate::repository::did_repository::mocks::MockDidRepository;

    pub struct TestPresets {
        pub from_did: String,
        pub from_keyring: KeyPairing,
        pub to_did: String,
        pub to_keyring: KeyPairing,
    }

    impl Default for TestPresets {
        fn default() -> Self {
            let trng = OSRandomNumberGenerator::default();

            TestPresets {
                from_did: "did:example:from".to_string(),
                from_keyring: KeyPairing::create_keyring(&trng).unwrap(),
                to_did: "did:example:to".to_string(),
                to_keyring: KeyPairing::create_keyring(&trng).unwrap(),
            }
        }
    }

    impl TestPresets {
        pub fn create_mock_did_repository(&self) -> MockDidRepository {
            MockDidRepository::from_pairs([
                (self.from_did.clone(), self.from_keyring.clone()),
                (self.to_did.clone(), self.to_keyring.clone()),
            ])
        }
    }
}
