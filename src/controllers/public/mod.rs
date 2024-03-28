use nodex_didcomm::keyring::keypair::KeyPairing;

pub mod nodex_create_didcomm_message;
pub mod nodex_create_identifier;
pub mod nodex_create_verifiable_message;
pub mod nodex_find_identifier;
pub mod nodex_receive;
pub mod nodex_verify_didcomm_message;
pub mod nodex_verify_verifiable_message;

fn get_my_did() -> String {
    let config = crate::app_config();
    let config = config.lock();
    config.get_did().unwrap().to_string()
}

fn get_my_keyring() -> KeyPairing {
    let config = crate::app_config();
    let config = config.lock();
    config.load_keyring().expect("failed to load keyring")
}
