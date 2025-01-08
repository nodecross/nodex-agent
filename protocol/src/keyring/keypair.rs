use hex::FromHexError;
use k256::elliptic_curve::sec1::ToEncodedPoint;
use rand_core::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use std::convert::{TryFrom, TryInto};
use thiserror::Error;
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct KeyPairHex {
    // MEMO: Matching schema in NodeX config.
    public_key: String,
    secret_key: String,
}

#[derive(Error, Debug)]
pub enum KeyPairingError {
    #[error("from hex error: {0}")]
    FromHex(#[from] FromHexError),
    #[error("crypt error: {0}")]
    Crypt(String),
}

pub trait KeyPair<S, P>: Sized {
    type Error: std::error::Error;
    fn get_secret_key(&self) -> S;
    fn get_public_key(&self) -> P;
    fn to_hex_key_pair(&self) -> KeyPairHex;
    fn from_hex_key_pair(kp: &KeyPairHex) -> Result<Self, Self::Error>;
}

#[derive(Clone)]
pub struct K256KeyPair {
    secret_key: k256::SecretKey,
    public_key: k256::PublicKey,
}

impl K256KeyPair {
    pub fn new(secret_key: k256::SecretKey) -> Self {
        let public_key = secret_key.public_key();
        K256KeyPair {
            public_key,
            secret_key,
        }
    }
}

impl KeyPair<k256::SecretKey, k256::PublicKey> for K256KeyPair {
    type Error = KeyPairingError;
    fn get_secret_key(&self) -> k256::SecretKey {
        self.secret_key.clone()
    }
    fn get_public_key(&self) -> k256::PublicKey {
        self.public_key
    }
    fn to_hex_key_pair(&self) -> KeyPairHex {
        let sk = self.secret_key.to_bytes();
        let secret_key = hex::encode(sk);
        let pk = self.public_key.to_encoded_point(false);
        let public_key = hex::encode(pk.as_bytes());
        KeyPairHex {
            secret_key,
            public_key,
        }
    }
    fn from_hex_key_pair(kp: &KeyPairHex) -> Result<Self, KeyPairingError> {
        let secret_key = hex::decode(&kp.secret_key)?;
        let secret_key = k256::SecretKey::from_slice(&secret_key)
            .map_err(|e| KeyPairingError::Crypt(e.to_string()))?;
        let public_key = hex::decode(&kp.public_key)?;
        let public_key = k256::PublicKey::from_sec1_bytes(&public_key)
            .map_err(|e| KeyPairingError::Crypt(e.to_string()))?;
        Ok(K256KeyPair {
            public_key,
            secret_key,
        })
    }
}

#[derive(Clone)]
pub struct X25519KeyPair {
    secret_key: x25519_dalek::StaticSecret,
    public_key: x25519_dalek::PublicKey,
}

impl X25519KeyPair {
    pub fn new(secret_key: x25519_dalek::StaticSecret) -> Self {
        let public_key = x25519_dalek::PublicKey::from(&secret_key);
        X25519KeyPair {
            public_key,
            secret_key,
        }
    }
}

impl KeyPair<x25519_dalek::StaticSecret, x25519_dalek::PublicKey> for X25519KeyPair {
    type Error = KeyPairingError;
    fn get_secret_key(&self) -> x25519_dalek::StaticSecret {
        self.secret_key.clone()
    }
    fn get_public_key(&self) -> x25519_dalek::PublicKey {
        self.public_key
    }
    fn to_hex_key_pair(&self) -> KeyPairHex {
        let sk = self.secret_key.as_bytes();
        let secret_key = hex::encode(sk);
        let pk = self.public_key.as_bytes();
        let public_key = hex::encode(pk);
        KeyPairHex {
            secret_key,
            public_key,
        }
    }
    fn from_hex_key_pair(kp: &KeyPairHex) -> Result<Self, KeyPairingError> {
        let secret_key = hex::decode(&kp.secret_key)?;
        let secret_key: [u8; 32] = secret_key.try_into().map_err(|e: Vec<u8>| {
            KeyPairingError::Crypt(format!("array length mismatch: {}", e.len()))
        })?;
        let secret_key = x25519_dalek::StaticSecret::from(secret_key);
        let public_key = hex::decode(&kp.public_key)?;
        let public_key: [u8; 32] = public_key.try_into().map_err(|e: Vec<u8>| {
            KeyPairingError::Crypt(format!("array length mismatch: {}", e.len()))
        })?;
        let public_key = x25519_dalek::PublicKey::from(public_key);
        Ok(X25519KeyPair {
            public_key,
            secret_key,
        })
    }
}

#[derive(Clone)]
pub struct Ed25519KeyPair {
    secret_key: ed25519_dalek::SigningKey,
    public_key: ed25519_dalek::VerifyingKey,
}

impl Ed25519KeyPair {
    pub fn new<R: rand_core::CryptoRngCore>(csprng: &mut R) -> Self {
        let secret_key = ed25519_dalek::SigningKey::generate(csprng);
        let public_key = secret_key.verifying_key();
        Ed25519KeyPair {
            public_key,
            secret_key,
        }
    }
}

impl KeyPair<ed25519_dalek::SigningKey, ed25519_dalek::VerifyingKey> for Ed25519KeyPair {
    type Error = KeyPairingError;
    fn get_secret_key(&self) -> ed25519_dalek::SigningKey {
        self.secret_key.clone()
    }
    fn get_public_key(&self) -> ed25519_dalek::VerifyingKey {
        self.public_key
    }
    fn to_hex_key_pair(&self) -> KeyPairHex {
        let sk = self.secret_key.as_bytes();
        let secret_key = hex::encode(sk);
        let pk = self.public_key.as_bytes();
        let public_key = hex::encode(pk);
        KeyPairHex {
            secret_key,
            public_key,
        }
    }
    fn from_hex_key_pair(kp: &KeyPairHex) -> Result<Self, KeyPairingError> {
        let secret_key = hex::decode(&kp.secret_key)?;
        let secret_key: [u8; 32] = secret_key.try_into().map_err(|e: Vec<u8>| {
            KeyPairingError::Crypt(format!("array length mismatch: {}", e.len()))
        })?;
        let secret_key = ed25519_dalek::SigningKey::from(secret_key);
        let public_key = hex::decode(&kp.public_key)?;
        let public_key: [u8; 32] = public_key.try_into().map_err(|e: Vec<u8>| {
            KeyPairingError::Crypt(format!("array length mismatch: {}", e.len()))
        })?;
        let public_key = ed25519_dalek::VerifyingKey::from_bytes(&public_key)
            .map_err(|e| KeyPairingError::Crypt(e.to_string()))?;

        Ok(Ed25519KeyPair {
            public_key,
            secret_key,
        })
    }
}

#[derive(Clone)]
pub struct KeyPairing {
    pub sign: K256KeyPair,
    pub sign_cbor: Ed25519KeyPair,
    pub update: K256KeyPair,
    pub recovery: K256KeyPair,
    pub encrypt: X25519KeyPair,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct KeyPairingHex {
    pub sign: KeyPairHex,
    pub sign_cbor: KeyPairHex,
    pub update: KeyPairHex,
    pub recovery: KeyPairHex,
    pub encrypt: KeyPairHex,
}

impl KeyPairing {
    pub fn create_keyring<T: RngCore + CryptoRng>(mut csprng: T) -> Self {
        let sign = K256KeyPair::new(k256::SecretKey::random(&mut csprng));
        let sign_cbor = Ed25519KeyPair::new(&mut csprng);
        let update = K256KeyPair::new(k256::SecretKey::random(&mut csprng));
        let recovery = K256KeyPair::new(k256::SecretKey::random(&mut csprng));
        let encrypt = X25519KeyPair::new(x25519_dalek::StaticSecret::random_from_rng(&mut csprng));
        KeyPairing {
            sign,
            sign_cbor,
            update,
            recovery,
            encrypt,
        }
    }
}

impl From<&KeyPairing> for KeyPairingHex {
    fn from(keypair: &KeyPairing) -> Self {
        KeyPairingHex {
            sign: keypair.sign.to_hex_key_pair(),
            sign_cbor: keypair.sign_cbor.to_hex_key_pair(),
            update: keypair.update.to_hex_key_pair(),
            recovery: keypair.recovery.to_hex_key_pair(),
            encrypt: keypair.encrypt.to_hex_key_pair(),
        }
    }
}

impl TryFrom<&KeyPairingHex> for KeyPairing {
    type Error = KeyPairingError;

    fn try_from(hex: &KeyPairingHex) -> Result<Self, Self::Error> {
        let sign = K256KeyPair::from_hex_key_pair(&hex.sign)?;
        let sign_cbor = Ed25519KeyPair::from_hex_key_pair(&hex.sign_cbor)?;
        let update = K256KeyPair::from_hex_key_pair(&hex.update)?;
        let recovery = K256KeyPair::from_hex_key_pair(&hex.recovery)?;
        let encrypt = X25519KeyPair::from_hex_key_pair(&hex.encrypt)?;

        Ok(KeyPairing {
            sign,
            sign_cbor,
            update,
            recovery,
            encrypt,
        })
    }
}

#[cfg(test)]
pub mod tests {
    use rand_core::OsRng;

    use super::*;

    #[test]
    pub fn test_create_keyring() {
        let keyring = KeyPairing::create_keyring(OsRng);

        assert_eq!(keyring.sign.get_secret_key().to_bytes().len(), 32);
        assert_eq!(keyring.sign_cbor.get_secret_key().to_bytes().len(), 32);
        assert_eq!(keyring.update.get_secret_key().to_bytes().len(), 32);
        assert_eq!(keyring.recovery.get_secret_key().to_bytes().len(), 32);
        assert_eq!(keyring.encrypt.get_secret_key().as_bytes().len(), 32);
    }
}
