use crate::{
    app_config,
    config::SingletonAppConfig,
    nodex::extension::secure_keystore::{SecureKeyStore, SecureKeyStoreError, SecureKeyStoreType},
};
use nodex_didcomm::keyring::{extension::trng::OSRandomNumberGenerator, secp256k1::Secp256k1};

use thiserror::Error;

pub struct KeyPairingWithConfig {
    sign: Secp256k1,
    update: Secp256k1,
    recovery: Secp256k1,
    encrypt: Secp256k1,
    config: Box<SingletonAppConfig>,
    secure_keystore: SecureKeyStore,
}

#[derive(Error, Debug)]
pub enum KeyPairingError {
    #[error("secure keystore error")]
    SecureKeyStoreError(#[from] SecureKeyStoreError),
    #[error("keyring error")]
    KeyPairingError(#[from] nodex_didcomm::keyring::keypair::KeyPairingError),
    #[error("key not found")]
    KeyNotFound,
    #[error("DID not found")]
    DIDNotFound,
}

impl KeyPairingWithConfig {
    pub fn load_keyring() -> Result<Self, KeyPairingError> {
        let config = app_config();
        let secure_keystore = SecureKeyStore::new();

        fn load_secp256k1(
            secure_keystore: &SecureKeyStore,
            key_type: SecureKeyStoreType,
        ) -> Result<Secp256k1, KeyPairingError> {
            let key_pair = secure_keystore
                .read(&key_type)?
                .ok_or(KeyPairingError::KeyNotFound)?;

            Ok(key_pair)
        }

        let sign = load_secp256k1(&secure_keystore, SecureKeyStoreType::Sign)?;
        let update = load_secp256k1(&secure_keystore, SecureKeyStoreType::Update)?;
        let recovery = load_secp256k1(&secure_keystore, SecureKeyStoreType::Recover)?;
        let encrypt = load_secp256k1(&secure_keystore, SecureKeyStoreType::Encrypt)?;

        Ok(KeyPairingWithConfig {
            sign,
            update,
            recovery,
            encrypt,
            config,
            secure_keystore,
        })
    }

    pub fn create_keyring() -> Result<Self, KeyPairingError> {
        let config = app_config();
        let secure_keystore = SecureKeyStore::new();

        // TODO: extension trng support
        let trng = OSRandomNumberGenerator::default();
        let keyring = nodex_didcomm::keyring::keypair::KeyPairing::create_keyring(&trng)?;

        Ok(KeyPairingWithConfig {
            sign: keyring.sign,
            update: keyring.update,
            recovery: keyring.recovery,
            encrypt: keyring.encrypt,
            config,
            secure_keystore,
        })
    }

    pub fn get_keyring(&self) -> nodex_didcomm::keyring::keypair::KeyPairing {
        nodex_didcomm::keyring::keypair::KeyPairing {
            sign: self.sign.clone(),
            update: self.update.clone(),
            recovery: self.recovery.clone(),
            encrypt: self.encrypt.clone(),
        }
    }

    pub fn save(&mut self, did: &str) {
        self.secure_keystore
            .write(&SecureKeyStoreType::Sign, &self.sign)
            .expect("failed to save sign key");
        self.secure_keystore
            .write(&SecureKeyStoreType::Update, &self.update)
            .expect("failed to save update key");
        self.secure_keystore
            .write(&SecureKeyStoreType::Recover, &self.recovery)
            .expect("failed to save recovery key");
        self.secure_keystore
            .write(&SecureKeyStoreType::Encrypt, &self.encrypt)
            .expect("failed to save encrypt key");

        let mut config = self.config.lock();
        config.save_did(did);
        config.save_is_initialized(true);
    }

    pub fn get_identifier(&self) -> Result<String, KeyPairingError> {
        self.config
            .lock()
            .get_did()
            .ok_or(KeyPairingError::DIDNotFound)
    }
}
