use crate::nodex::runtime;
use crate::nodex::runtime::base64_url::PaddingType;
use crate::nodex::sidetree::payload::PublicKeyPayload;
use hex;
use ibig::{ibig, IBig};
use serde::{Deserialize, Serialize};
use std::cmp::Ordering;
use thiserror::Error;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KeyPairSecp256K1 {
    #[serde(rename = "kty")]
    pub kty: String,

    #[serde(rename = "crv")]
    pub crv: String,

    #[serde(rename = "x")]
    pub x: String,

    #[serde(rename = "y")]
    pub y: String,

    #[serde(rename = "d", skip_serializing_if = "Option::is_none")]
    pub d: Option<String>,

    #[serde(rename = "kid", skip_serializing_if = "Option::is_none")]
    pub kid: Option<String>,
}

#[derive(Clone, Debug)]
pub struct Secp256k1Context {
    pub public: Vec<u8>,
    pub secret: Vec<u8>,
}

#[allow(dead_code)]
#[derive(Clone, Debug)]
pub struct Secp256k1HexKeyPair {
    public: String,
    private: String,
}

#[derive(Clone, Debug)]
pub struct Secp256k1 {
    public: Vec<u8>,
    private: Vec<u8>,
}

#[derive(Error, Debug)]
pub enum Secp256k1Error {
    #[error("Invalid public key size")]
    InvalidSecretKeySize,
    #[error("Secp256k1 runtime error : {0:?}")]
    Secp256k1RuntimeError(#[from] runtime::secp256k1::Secp256k1Error),
    #[error("Invalid public key size")]
    InvalidPublicKeySize,
    #[error("Base64 decode error")]
    Base64UrlError(#[from] runtime::base64_url::Base64UrlError),
    #[error("Invalid first bytes")]
    InvalidFirstBytes,
    #[error("Number parsing error")]
    NumberParsingError(#[from] ibig::error::ParseError),
    #[error("Validation Failed")]
    ValidationFailed,
}

impl Secp256k1 {
    const PRIVATE_KEY_SIZE: usize = 32; // Buffer(PrivateKey (32 = 256 bit))
    const COMPRESSED_PUBLIC_KEY_SIZE: usize = 33; // Buffer(0x04 + PublicKey (32 = 256 bit))
    const UNCOMPRESSED_PUBLIC_KEY_SIZE: usize = 65; // Buffer(0x04 + PublicKey (64 = 512 bit))

    pub fn new(context: &Secp256k1Context) -> Result<Self, Secp256k1Error> {
        if context.secret.len() != Self::PRIVATE_KEY_SIZE {
            return Err(Secp256k1Error::InvalidSecretKeySize);
        }

        if context.public.len() == Self::COMPRESSED_PUBLIC_KEY_SIZE {
            let public = Secp256k1::transform_uncompressed_public_key(&context.public)?;

            Ok(Secp256k1 {
                public,
                private: context.secret.clone(),
            })
        } else if context.public.len() == Self::UNCOMPRESSED_PUBLIC_KEY_SIZE {
            Ok(Secp256k1 {
                public: context.public.clone(),
                private: context.secret.clone(),
            })
        } else {
            Err(Secp256k1Error::InvalidPublicKeySize)
        }
    }

    pub fn get_public_key(&self) -> Vec<u8> {
        self.public.clone()
    }

    pub fn get_secret_key(&self) -> Vec<u8> {
        self.private.clone()
    }

    #[allow(dead_code)]
    pub fn to_hex_key_pair(&self) -> Secp256k1HexKeyPair {
        Secp256k1HexKeyPair {
            public: hex::encode(self.get_public_key()),
            private: hex::encode(self.get_secret_key()),
        }
    }

    pub fn from_jwk(jwk: &KeyPairSecp256K1) -> Result<Self, Secp256k1Error> {
        let d = match jwk.d.clone() {
            Some(v) => v,
            None => {
                let noop: Vec<u8> = (0..Self::PRIVATE_KEY_SIZE).map(|_| 0x00).collect();
                runtime::base64_url::Base64Url::encode(&noop, &PaddingType::NoPadding)
            }
        };

        let x = runtime::base64_url::Base64Url::decode_as_bytes(&jwk.x, &PaddingType::NoPadding)?;
        let y = runtime::base64_url::Base64Url::decode_as_bytes(&jwk.y, &PaddingType::NoPadding)?;

        let public = [&[0x04], &x[..], &y[..]].concat();
        let private = runtime::base64_url::Base64Url::decode_as_bytes(&d, &PaddingType::NoPadding)?;

        Ok(Secp256k1 { public, private })
    }

    pub fn to_jwk(&self, included_private_key: bool) -> Result<KeyPairSecp256K1, Secp256k1Error> {
        let validated = self.validate_point()?;

        if !validated {
            return Err(Secp256k1Error::ValidationFailed);
        }

        let x = self.get_point_x()?;
        let y = self.get_point_y()?;

        if included_private_key {
            Ok(KeyPairSecp256K1 {
                kty: "EC".to_string(),
                crv: "secp256k1".to_string(),
                x: runtime::base64_url::Base64Url::encode(&x, &PaddingType::NoPadding),
                y: runtime::base64_url::Base64Url::encode(&y, &PaddingType::NoPadding),
                d: Some(runtime::base64_url::Base64Url::encode(
                    &self.get_secret_key(),
                    &PaddingType::NoPadding,
                )),
                kid: None,
            })
        } else {
            Ok(KeyPairSecp256K1 {
                kty: "EC".to_string(),
                crv: "secp256k1".to_string(),
                x: runtime::base64_url::Base64Url::encode(&x, &PaddingType::NoPadding),
                y: runtime::base64_url::Base64Url::encode(&y, &PaddingType::NoPadding),
                d: None,
                kid: None,
            })
        }
    }

    pub fn to_public_key(
        &self,
        key_id: &str,
        purpose: &[&str],
    ) -> Result<PublicKeyPayload, Secp256k1Error> {
        let validated = self.validate_point()?;

        if !validated {
            return Err(Secp256k1Error::ValidationFailed);
        }

        let jwk = self.to_jwk(false)?;

        Ok(PublicKeyPayload {
            id: key_id.to_string(),
            r#type: "EcdsaSecp256k1VerificationKey2019".to_string(),
            jwk,
            purpose: purpose
                .to_vec()
                .iter()
                .map(|value| value.to_string())
                .collect(),
        })
    }

    pub fn get_point_x(&self) -> Result<Vec<u8>, Secp256k1Error> {
        let public = self.get_public_key();

        if public.len() != Self::UNCOMPRESSED_PUBLIC_KEY_SIZE {
            return Err(Secp256k1Error::InvalidPublicKeySize);
        }
        if public[0] != 0x04 {
            return Err(Secp256k1Error::InvalidFirstBytes);
        }

        let (_, n) = public.split_at(1);
        let (s, _) = n.split_at(32);

        Ok(s.to_vec())
    }

    pub fn get_point_y(&self) -> Result<Vec<u8>, Secp256k1Error> {
        let public = self.get_public_key();

        if public.len() != Self::UNCOMPRESSED_PUBLIC_KEY_SIZE {
            return Err(Secp256k1Error::InvalidPublicKeySize);
        }
        if public[0] != 0x04 {
            return Err(Secp256k1Error::InvalidFirstBytes);
        }

        let (_, n) = public.split_at(1);
        let (_, s) = n.split_at(32);

        Ok(s.to_vec())
    }

    pub fn validate_point(&self) -> Result<bool, Secp256k1Error> {
        let x = self.get_point_x()?;
        let y = self.get_point_y()?;

        let nx = IBig::from_str_radix(&hex::encode(x), 16)?;
        let ny = IBig::from_str_radix(&hex::encode(y), 16)?;
        let np = IBig::from_str_radix(
            "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F",
            16,
        )?;

        let verified: IBig = (&ny * &ny - &nx * &nx * &nx - 7) % &np;

        Ok(verified.cmp(&ibig!(0)) == Ordering::Equal)
    }

    pub fn transform_uncompressed_public_key(compressed: &[u8]) -> Result<Vec<u8>, Secp256k1Error> {
        runtime::secp256k1::Secp256k1::convert_public_key(compressed, false).map_err(|e| e.into())
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use rstest::*;

    #[fixture]
    fn private_key() -> Vec<u8> {
        vec![
            0xc7, 0x39, 0x80, 0x5a, 0xb0, 0x3d, 0xa6, 0x2d, 0xdb, 0xe0, 0x33, 0x90, 0xac, 0xdf,
            0x76, 0x15, 0x64, 0x0a, 0xa6, 0xed, 0x31, 0xb8, 0xf1, 0x82, 0x43, 0xf0, 0x4a, 0x57,
            0x2c, 0x52, 0x8e, 0xdb,
        ]
    }

    #[fixture]
    fn public_key() -> Vec<u8> {
        vec![
            0x02, 0x70, 0x96, 0x45, 0x32, 0xf0, 0x83, 0xf4, 0x5f, 0xe8, 0xe8, 0xcc, 0xea, 0x96,
            0xa2, 0x2f, 0x60, 0x18, 0xd4, 0x6a, 0x40, 0x6f, 0x58, 0x3a, 0xb2, 0x26, 0xb1, 0x92,
            0x83, 0xaa, 0x60, 0x5c, 0x44,
        ]
    }

    #[test]
    pub fn test_to_hex_key_pair() {
        let node = match Secp256k1::new(&Secp256k1Context {
            public: public_key(),
            secret: private_key(),
        }) {
            Ok(v) => v,
            Err(_) => panic!(),
        };

        let result = node.to_hex_key_pair();

        assert_eq!(
            result.private,
            "c739805ab03da62ddbe03390acdf7615640aa6ed31b8f18243f04a572c528edb"
        );
        assert_eq!(result.public, "0470964532f083f45fe8e8ccea96a22f6018d46a406f583ab226b19283aa605c44851b9274e6a2ce2ad42b4169e37df5f6cb38e81604b3ca2ebe11dd085862b490");
    }

    #[test]
    pub fn test_get_point_x() {
        let node = match Secp256k1::new(&Secp256k1Context {
            public: public_key(),
            secret: private_key(),
        }) {
            Ok(v) => v,
            Err(_) => panic!(),
        };

        let result = match node.get_point_x() {
            Ok(v) => v,
            Err(_) => panic!(),
        };

        assert_eq!(
            result,
            vec![
                0x70, 0x96, 0x45, 0x32, 0xf0, 0x83, 0xf4, 0x5f, 0xe8, 0xe8, 0xcc, 0xea, 0x96, 0xa2,
                0x2f, 0x60, 0x18, 0xd4, 0x6a, 0x40, 0x6f, 0x58, 0x3a, 0xb2, 0x26, 0xb1, 0x92, 0x83,
                0xaa, 0x60, 0x5c, 0x44,
            ]
        )
    }

    #[test]
    pub fn test_get_point_y() {
        let node = match Secp256k1::new(&Secp256k1Context {
            public: public_key(),
            secret: private_key(),
        }) {
            Ok(v) => v,
            Err(_) => panic!(),
        };

        let result = match node.get_point_y() {
            Ok(v) => v,
            Err(_) => panic!(),
        };

        assert_eq!(
            result,
            vec![
                0x85, 0x1b, 0x92, 0x74, 0xe6, 0xa2, 0xce, 0x2a, 0xd4, 0x2b, 0x41, 0x69, 0xe3, 0x7d,
                0xf5, 0xf6, 0xcb, 0x38, 0xe8, 0x16, 0x04, 0xb3, 0xca, 0x2e, 0xbe, 0x11, 0xdd, 0x08,
                0x58, 0x62, 0xb4, 0x90,
            ]
        )
    }

    #[test]
    pub fn test_validate_point() {
        let node = match Secp256k1::new(&Secp256k1Context {
            public: public_key(),
            secret: private_key(),
        }) {
            Ok(v) => v,
            Err(_) => panic!(),
        };

        let result = match node.validate_point() {
            Ok(v) => v,
            Err(_) => panic!(),
        };

        assert!(result)
    }

    #[test]
    pub fn test_to_jwk_with_private_key() {
        let node = match Secp256k1::new(&Secp256k1Context {
            public: public_key(),
            secret: private_key(),
        }) {
            Ok(v) => v,
            Err(_) => panic!(),
        };

        let result = match node.to_jwk(true) {
            Ok(v) => v,
            Err(_) => panic!(),
        };

        assert_eq!(result.kty, "EC");
        assert_eq!(result.crv, "secp256k1");
        assert_eq!(result.x, "cJZFMvCD9F_o6MzqlqIvYBjUakBvWDqyJrGSg6pgXEQ");
        assert_eq!(result.y, "hRuSdOaizirUK0Fp43319ss46BYEs8ouvhHdCFhitJA");
        assert_eq!(
            result.d,
            Some("xzmAWrA9pi3b4DOQrN92FWQKpu0xuPGCQ_BKVyxSjts".to_string())
        );
        assert_eq!(result.kid, None);
    }

    #[test]
    pub fn test_to_jwk_without_private_key() {
        let node = match Secp256k1::new(&Secp256k1Context {
            public: public_key(),
            secret: private_key(),
        }) {
            Ok(v) => v,
            Err(_) => panic!(),
        };

        let result = match node.to_jwk(false) {
            Ok(v) => v,
            Err(_) => panic!(),
        };

        assert_eq!(result.kty, "EC");
        assert_eq!(result.crv, "secp256k1");
        assert_eq!(result.x, "cJZFMvCD9F_o6MzqlqIvYBjUakBvWDqyJrGSg6pgXEQ");
        assert_eq!(result.y, "hRuSdOaizirUK0Fp43319ss46BYEs8ouvhHdCFhitJA");
        assert_eq!(result.d, None);
        assert_eq!(result.kid, None);
    }

    #[test]
    pub fn test_from_jwk_with_private_key() {
        let node = match Secp256k1::new(&Secp256k1Context {
            public: public_key(),
            secret: private_key(),
        }) {
            Ok(v) => v,
            Err(_) => panic!(),
        };

        let jwk = match node.to_jwk(false) {
            Ok(v) => v,
            Err(_) => panic!(),
        };

        let clone = match Secp256k1::from_jwk(&jwk) {
            Ok(v) => v,
            Err(_) => panic!(),
        };

        assert_eq!(clone.get_public_key(), node.get_public_key());
        assert_eq!(
            clone.get_secret_key(),
            vec![
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00,
            ]
        );
    }

    #[test]
    pub fn test_from_jwk_without_private_key() {
        let node = match Secp256k1::new(&Secp256k1Context {
            public: public_key(),
            secret: private_key(),
        }) {
            Ok(v) => v,
            Err(_) => panic!(),
        };

        let jwk = match node.to_jwk(true) {
            Ok(v) => v,
            Err(_) => panic!(),
        };

        let clone = match Secp256k1::from_jwk(&jwk) {
            Ok(v) => v,
            Err(_) => panic!(),
        };

        assert_eq!(clone.get_public_key(), node.get_public_key());
        assert_eq!(clone.get_secret_key(), node.get_secret_key());
    }
}
