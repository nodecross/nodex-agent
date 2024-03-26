use nodex_didcomm::keyring::keypair::KeyPairing;

pub mod hub;
pub mod nodex;
pub mod project_verifier;

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
