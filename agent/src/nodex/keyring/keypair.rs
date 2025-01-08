use crate::{
    config::SingletonAppConfig,
    nodex::extension::secure_keystore::{SecureKeyStore, SecureKeyStoreKey},
};
use protocol::keyring::keypair::{Ed25519KeyPair, K256KeyPair, X25519KeyPair};
use protocol::rand_core::OsRng;
use thiserror::Error;

pub struct KeyPairingWithConfig<S: SecureKeyStore> {
    sign: K256KeyPair,
    sign_cbor: Ed25519KeyPair,
    update: K256KeyPair,
    recovery: K256KeyPair,
    encrypt: X25519KeyPair,
    config: Box<SingletonAppConfig>,
    secure_keystore: S,
}

#[derive(Error, Debug)]
pub enum KeyPairingError {
    #[error("create keyring failed: {0}")]
    CreateKeyringFailed(#[from] protocol::keyring::keypair::KeyPairingError),
    #[error("key not found")]
    KeyNotFound,
    #[error("DID not found")]
    DidNotFound,
}

impl<S: SecureKeyStore> KeyPairingWithConfig<S> {
    pub fn load_keyring(
        config: Box<SingletonAppConfig>,
        secure_keystore: S,
    ) -> Result<Self, KeyPairingError> {
        let sign = secure_keystore
            .read_sign()
            .ok_or(KeyPairingError::KeyNotFound)?;
        let sign_cbor = secure_keystore
            .read_sign_cbor()
            .ok_or(KeyPairingError::KeyNotFound)?;
        let update = secure_keystore
            .read_update()
            .ok_or(KeyPairingError::KeyNotFound)?;
        let recovery = secure_keystore
            .read_recovery()
            .ok_or(KeyPairingError::KeyNotFound)?;
        let encrypt = secure_keystore
            .read_encrypt()
            .ok_or(KeyPairingError::KeyNotFound)?;

        Ok(KeyPairingWithConfig {
            sign,
            sign_cbor,
            update,
            recovery,
            encrypt,
            config,
            secure_keystore,
        })
    }

    pub fn create_keyring(config: Box<SingletonAppConfig>, secure_keystore: S) -> Self {
        // TODO: extension trng support
        let keyring = protocol::keyring::keypair::KeyPairing::create_keyring(OsRng);

        KeyPairingWithConfig {
            sign: keyring.sign,
            sign_cbor: keyring.sign_cbor,
            update: keyring.update,
            recovery: keyring.recovery,
            encrypt: keyring.encrypt,
            config,
            secure_keystore,
        }
    }

    pub fn get_keyring(&self) -> protocol::keyring::keypair::KeyPairing {
        protocol::keyring::keypair::KeyPairing {
            sign: self.sign.clone(),
            sign_cbor: self.sign_cbor.clone(),
            update: self.update.clone(),
            recovery: self.recovery.clone(),
            encrypt: self.encrypt.clone(),
        }
    }

    pub fn save(self, did: &str) {
        let Self {
            sign,
            sign_cbor,
            update,
            recovery,
            encrypt,
            config,
            secure_keystore,
        } = self;
        secure_keystore.write(&SecureKeyStoreKey::Sign(sign));
        secure_keystore.write(&SecureKeyStoreKey::SignCbor(sign_cbor));
        secure_keystore.write(&SecureKeyStoreKey::Update(update));
        secure_keystore.write(&SecureKeyStoreKey::Recovery(recovery));
        secure_keystore.write(&SecureKeyStoreKey::Encrypt(encrypt));
        {
            let mut config = config.lock();
            config.save_did(did);
            config.save_is_initialized(true);
        }
    }

    pub fn get_identifier(&self) -> Result<String, KeyPairingError> {
        self.config
            .lock()
            .get_did()
            .ok_or(KeyPairingError::DidNotFound)
    }
}
