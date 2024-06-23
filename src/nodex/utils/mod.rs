pub mod sidetree_client;
pub mod studio_client;

use nodex_didcomm::keyring::keypair::KeyPairing;

pub fn get_my_did() -> String {
    let config = crate::app_config();
    let config = config.lock();
    config.get_did().unwrap().to_string()
}

pub fn get_my_keyring() -> KeyPairing {
    let config = crate::app_config();
    let config = config.lock();
    config.load_keyring().expect("failed to load keyring")
}
