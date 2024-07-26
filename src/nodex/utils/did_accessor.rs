use nodex_didcomm::keyring::keypair::KeyPairing;

pub trait DidAccessor {
    fn get_my_did(&self) -> String;
    fn get_my_keyring(&self) -> KeyPairing;
}

pub struct DIDAccessorImpl {}

impl DidAccessor for DIDAccessorImpl {
    fn get_my_did(&self) -> String {
        let config = crate::app_config();
        let config = config.lock();
        config.get_did().unwrap().to_string()
    }

    fn get_my_keyring(&self) -> KeyPairing {
        let config = crate::app_config();
        let config = config.lock();
        config.load_keyring().expect("failed to load keyring")
    }
}

#[cfg(test)]
pub mod mocks {
    use super::*;

    pub struct MockDIDAccessor {
        my_did: String,
        my_keyring: KeyPairing,
    }

    impl MockDIDAccessor {
        pub fn new(my_did: String, my_keyring: KeyPairing) -> MockDIDAccessor {
            MockDIDAccessor { my_did, my_keyring }
        }
    }

    impl DidAccessor for MockDIDAccessor {
        fn get_my_did(&self) -> String {
            self.my_did.clone()
        }

        fn get_my_keyring(&self) -> KeyPairing {
            self.my_keyring.clone()
        }
    }
}
