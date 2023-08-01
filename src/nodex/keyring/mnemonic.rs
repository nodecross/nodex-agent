use std::cmp::Ordering;

use crate::{
    app_config,
    config::KeyPair,
    nodex::{
        errors::NodeXError,
        extension::secure_keystore::{SecureKeyStore, SecureKeyStoreType},
        runtime,
    },
    SingletonAppConfig,
};

use bip32::Seed;

use super::secp256k1::{Secp256k1, Secp256k1Context};

pub struct MnemonicKeyring {
    // mnemonic: String,
    sign: Secp256k1,
    update: Secp256k1,
    recovery: Secp256k1,
    encrypt: Secp256k1,
    config: Box<SingletonAppConfig>,
    secure_keystore: SecureKeyStore,
}

impl MnemonicKeyring {
    const SIGN_DERIVATION_PATH: &'static str = "m/44'/0'/0'/0/10";
    const UPDATE_DERIVATION_PATH: &'static str = "m/44'/0'/0'/0/20";
    const RECOVERY_DERIVATION_PATH: &'static str = "m/44'/0'/0'/0/30";
    const ENCRYPT_DERIVATION_PATH: &'static str = "m/44'/0'/0'/0/40";

    pub fn load_keyring() -> Result<Self, NodeXError> {
        let config = app_config();
        let secure_keystore = SecureKeyStore::new();

        // let mnemonic = config.inner.lock().unwrap().get_mnemonic();
        // let mnemonic = match mnemonic {
        //     Some(v) => v,
        //     None => return Err(NodeXError {}),
        // };

        let sign = match secure_keystore.read(&SecureKeyStoreType::Sign) {
            Ok(Some(v)) => {
                match Secp256k1::new(&Secp256k1Context {
                    public: v.public_key,
                    secret: v.secret_key,
                }) {
                    Ok(v) => v,
                    _ => return Err(NodeXError {}),
                }
            }
            _ => return Err(NodeXError {}),
        };
        let update = match secure_keystore.read(&SecureKeyStoreType::Update) {
            Ok(Some(v)) => {
                match Secp256k1::new(&Secp256k1Context {
                    public: v.public_key,
                    secret: v.secret_key,
                }) {
                    Ok(v) => v,
                    _ => return Err(NodeXError {}),
                }
            }
            _ => return Err(NodeXError {}),
        };
        let recovery = match secure_keystore.read(&SecureKeyStoreType::Recover) {
            Ok(Some(v)) => {
                match Secp256k1::new(&Secp256k1Context {
                    public: v.public_key,
                    secret: v.secret_key,
                }) {
                    Ok(v) => v,
                    _ => return Err(NodeXError {}),
                }
            }
            _ => return Err(NodeXError {}),
        };
        let encrypt = match secure_keystore.read(&SecureKeyStoreType::Encrypt) {
            Ok(Some(v)) => {
                match Secp256k1::new(&Secp256k1Context {
                    public: v.public_key,
                    secret: v.secret_key,
                }) {
                    Ok(v) => v,
                    _ => return Err(NodeXError {}),
                }
            }
            _ => return Err(NodeXError {}),
        };

        Ok(MnemonicKeyring {
            // mnemonic,
            sign,
            update,
            recovery,
            encrypt,
            config,
            secure_keystore,
        })
    }

    pub fn create_keyring() -> Result<Self, NodeXError> {
        let config = app_config();
        let secure_keystore = SecureKeyStore::new();

        // let mnemonic = match runtime::bip39::BIP39::generate_mnemonic(
        //     &runtime::bip39::MnemonicType::Words24,
        // ) {
        //     Ok(v) => v,
        //     Err(e) => {
        //         log::error!("{:?}", e);
        //         return Err(NodeXError {});
        //     }
        // };
        // let seed = match runtime::bip39::BIP39::mnemonic_to_seed(&mnemonic, None) {
        //     Ok(v) => v,
        //     Err(e) => {
        //         log::error!("{:?}", e);
        //         return Err(NodeXError {});
        //     }
        // };

        let seed = Seed::new([0u8; 64]).as_bytes().to_vec();

        let sign = match Self::generate_secp256k1(&seed, Self::SIGN_DERIVATION_PATH) {
            Ok(v) => v,
            Err(e) => {
                log::error!("{:?}", e);
                return Err(NodeXError {});
            }
        };
        let update = match Self::generate_secp256k1(&seed, Self::UPDATE_DERIVATION_PATH) {
            Ok(v) => v,
            Err(e) => {
                log::error!("{:?}", e);
                return Err(NodeXError {});
            }
        };
        let recovery = match Self::generate_secp256k1(&seed, Self::RECOVERY_DERIVATION_PATH) {
            Ok(v) => v,
            Err(e) => {
                log::error!("{:?}", e);
                return Err(NodeXError {});
            }
        };
        let encrypt = match Self::generate_secp256k1(&seed, Self::ENCRYPT_DERIVATION_PATH) {
            Ok(v) => v,
            Err(e) => {
                log::error!("{:?}", e);
                return Err(NodeXError {});
            }
        };

        Ok(MnemonicKeyring {
            // mnemonic,
            sign,
            update,
            recovery,
            encrypt,
            config,
            secure_keystore,
        })
    }

    pub fn get_sign_key_pair(&self) -> Secp256k1 {
        self.sign.clone()
    }

    pub fn get_update_key_pair(&self) -> Secp256k1 {
        self.update.clone()
    }

    pub fn get_recovery_key_pair(&self) -> Secp256k1 {
        self.recovery.clone()
    }

    pub fn get_encrypt_key_pair(&self) -> Secp256k1 {
        self.encrypt.clone()
    }

    pub fn generate_secp256k1(seed: &[u8], derivation_path: &str) -> Result<Secp256k1, NodeXError> {
        let node = match runtime::bip32::BIP32::get_node(seed, derivation_path) {
            Ok(v) => v,
            Err(e) => {
                log::error!("{:?}", e);
                return Err(NodeXError {});
            }
        };

        match Secp256k1::new(&Secp256k1Context {
            public: node.public_key,
            secret: node.private_key,
        }) {
            Ok(v) => Ok(v),
            Err(e) => {
                log::error!("{:?}", e);
                Err(NodeXError {})
            }
        }
    }

    pub fn save(&mut self, did: &str) {
        match self.secure_keystore.write(
            &SecureKeyStoreType::Sign,
            &KeyPair {
                public_key: self.get_sign_key_pair().get_public_key(),
                secret_key: self.get_sign_key_pair().get_secret_key(),
            },
        ) {
            Ok(_) => (),
            _ => panic!(),
        };
        match self.secure_keystore.write(
            &SecureKeyStoreType::Update,
            &KeyPair {
                public_key: self.get_update_key_pair().get_public_key(),
                secret_key: self.get_update_key_pair().get_secret_key(),
            },
        ) {
            Ok(_) => (),
            _ => panic!(),
        };
        match self.secure_keystore.write(
            &SecureKeyStoreType::Recover,
            &KeyPair {
                public_key: self.get_recovery_key_pair().get_public_key(),
                secret_key: self.get_recovery_key_pair().get_secret_key(),
            },
        ) {
            Ok(_) => (),
            _ => panic!(),
        };
        match self.secure_keystore.write(
            &SecureKeyStoreType::Encrypt,
            &KeyPair {
                public_key: self.get_encrypt_key_pair().get_public_key(),
                secret_key: self.get_encrypt_key_pair().get_secret_key(),
            },
        ) {
            Ok(_) => (),
            _ => panic!(),
        };

        match self.config.inner.lock() {
            Ok(mut config) => config.save_did(did),
            _ => panic!(),
        };

        match self.config.inner.lock() {
            Ok(mut config) => {
                // config.save_mnemonic(&self.mnemonic);
            }
            _ => panic!(),
        };

        match self.config.inner.lock() {
            Ok(mut config) => {
                config.save_is_initialized(true);
            }
            _ => panic!(),
        }
    }

    pub fn get_identifier(&self) -> Result<String, NodeXError> {
        let did = self.config.inner.lock().unwrap().get_did();

        match did {
            Some(v) => Ok(v),
            None => Err(NodeXError {}),
        }
    }

    // #[allow(dead_code)]
    // pub fn get_mnemonic_phrase(&self) -> Result<Vec<String>, NodeXError> {
    //     Ok(self.mnemonic.split(' ').map(|v| v.to_string()).collect())
    // }

    // #[allow(dead_code)]
    // pub fn verify_mnemonic_phrase(&self, phrase: &Vec<String>) -> Result<bool, NodeXError> {
    //     let mnemonic = match self.get_mnemonic_phrase() {
    //         Ok(v) => v,
    //         Err(e) => {
    //             log::error!("{:?}", e);
    //             return Err(NodeXError {});
    //         }
    //     };

    //     Ok(mnemonic.cmp(phrase) == Ordering::Equal)
    // }
}

#[cfg(test)]
pub mod tests {
    use super::*;

    #[test]
    pub fn test_create_keyring() {
        let keyring = match MnemonicKeyring::create_keyring() {
            Ok(v) => v,
            Err(_) => panic!(),
        };

        assert_eq!(keyring.get_sign_key_pair().get_secret_key().len(), 32);
        assert_eq!(keyring.get_update_key_pair().get_secret_key().len(), 32);
        assert_eq!(keyring.get_recovery_key_pair().get_secret_key().len(), 32);
        assert_eq!(keyring.get_encrypt_key_pair().get_secret_key().len(), 32);
    }

    // #[test]
    // pub fn test_get_mnemonic_phrase() {
    //     let keyring = match MnemonicKeyring::create_keyring() {
    //         Ok(v) => v,
    //         Err(_) => panic!(),
    //     };

    //     let result = match keyring.get_mnemonic_phrase() {
    //         Ok(v) => v,
    //         Err(_) => panic!(),
    //     };

    //     assert_eq!(result.len(), 24)
    // }

    // #[test]
    // pub fn test_verify_mnemonic_phrase() {
    //     let keyring = match MnemonicKeyring::create_keyring() {
    //         Ok(v) => v,
    //         Err(_) => panic!(),
    //     };

    //     let mnemonic = match keyring.get_mnemonic_phrase() {
    //         Ok(v) => v,
    //         Err(_) => panic!(),
    //     };

    //     let result = match keyring.verify_mnemonic_phrase(&mnemonic) {
    //         Ok(v) => v,
    //         Err(_) => panic!(),
    //     };

    //     assert!(result)
    // }
}
