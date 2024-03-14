use hmac::digest::generic_array::GenericArray;
use k256::elliptic_curve::ecdh::diffie_hellman;
use k256::{
    ecdsa::{
        signature::{Signer, Verifier},
        Signature, SigningKey, VerifyingKey,
    },
    elliptic_curve::sec1::ToEncodedPoint,
    PublicKey, SecretKey,
};
use thiserror::Error;

pub struct Secp256k1 {}

#[derive(Debug, Error)]
pub enum Secp256k1Error {
    #[error("SecretKeyConvertError")]
    KeyConvertError(#[from] k256::elliptic_curve::Error),
    #[error("PublicKeyConvertError : {0:?}")]
    SignatureError(#[from] k256::ecdsa::Error),
    #[error("invalid signature length: {0}")]
    InvalidSignatureLength(usize),
}

impl Secp256k1 {
    pub fn ecdh(private_key: &[u8], public_key: &[u8]) -> Result<Vec<u8>, Secp256k1Error> {
        let sk = SecretKey::from_slice(private_key)?;
        let pk = PublicKey::from_sec1_bytes(public_key)?;

        Ok(diffie_hellman(sk.to_nonzero_scalar(), pk.as_affine())
            .raw_secret_bytes()
            .to_vec())
    }

    #[allow(dead_code)]
    pub fn generate_public_key(private_key: &[u8]) -> Result<Vec<u8>, Secp256k1Error> {
        let signing_key = SigningKey::from_slice(private_key.to_vec().as_slice())?;

        Ok(signing_key.verifying_key().to_sec1_bytes().to_vec())
    }

    #[allow(dead_code)]
    pub fn convert_public_key(
        public_key: &[u8],
        compress: bool,
    ) -> Result<Vec<u8>, Secp256k1Error> {
        let public_key = PublicKey::from_sec1_bytes(public_key)?;
        Ok(public_key.to_encoded_point(compress).as_bytes().to_vec())
    }

    #[allow(dead_code)]
    pub fn ecdsa_sign(message: &[u8], private_key: &[u8]) -> Result<Vec<u8>, Secp256k1Error> {
        let signing_key = SigningKey::from_slice(private_key.to_vec().as_slice())?;

        let signature: Signature = signing_key.try_sign(message.to_vec().as_slice())?;

        Ok(signature.to_vec())
    }

    pub fn ecdsa_verify(
        signature: &[u8],
        message: &[u8],
        public_key: &[u8],
    ) -> Result<bool, Secp256k1Error> {
        let verify_key = VerifyingKey::from_sec1_bytes(public_key)?;

        if signature.len() != 64 {
            return Err(Secp256k1Error::InvalidSignatureLength(signature.len()));
        }

        let r = GenericArray::from_slice(&signature[0..32]);
        let s = GenericArray::from_slice(&signature[32..]);

        let wrapped_signature = Signature::from_scalars(*r, *s)?;

        match verify_key.verify(message, &wrapped_signature) {
            Ok(()) => Ok(true),
            Err(e) => {
                log::error!("{:?}", e);
                Ok(false)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::*;

    #[fixture]
    fn message() -> String {
        String::from("0123456789abcdef")
    }

    #[fixture]
    fn private_key() -> Vec<u8> {
        vec![
            0x03, 0xb4, 0xad, 0xcd, 0x59, 0x36, 0x3f, 0x4e, 0xb9, 0xd0, 0x9f, 0x2a, 0x34, 0xcd,
            0x3d, 0x26, 0xa8, 0x12, 0x33, 0x0c, 0x2f, 0x88, 0x7c, 0xe5, 0xf8, 0x53, 0x89, 0x48,
            0xff, 0xac, 0x74, 0xc0,
        ]
    }

    #[test]
    fn test() {
        let shared_1 = match Secp256k1::ecdh(
            &private_key(),
            &[
                0x02, 0x51, 0x84, 0x22, 0x3f, 0xe8, 0x5d, 0x53, 0x20, 0x3c, 0xf9, 0xd3, 0x7f, 0x68,
                0x22, 0xe6, 0x33, 0xe8, 0xd7, 0x9f, 0x48, 0xb1, 0x32, 0xdf, 0x0b, 0x8c, 0x8a, 0x64,
                0x11, 0x41, 0xf3, 0x19, 0xb6,
            ],
        ) {
            Ok(v) => v,
            Err(_) => panic!(),
        };

        let shared_2 = match Secp256k1::ecdh(
            &private_key(),
            &[
                0x04, 0x51, 0x84, 0x22, 0x3f, 0xe8, 0x5d, 0x53, 0x20, 0x3c, 0xf9, 0xd3, 0x7f, 0x68,
                0x22, 0xe6, 0x33, 0xe8, 0xd7, 0x9f, 0x48, 0xb1, 0x32, 0xdf, 0x0b, 0x8c, 0x8a, 0x64,
                0x11, 0x41, 0xf3, 0x19, 0xb6, 0xa3, 0x70, 0x7c, 0xa5, 0x18, 0x61, 0xe1, 0xe2, 0xde,
                0xa4, 0x3c, 0x23, 0x84, 0xf1, 0x79, 0xed, 0x44, 0xe9, 0x8c, 0x4a, 0xd0, 0x38, 0x89,
                0x21, 0xd9, 0x6a, 0x1e, 0x05, 0x93, 0x15, 0xe7, 0x54,
            ],
        ) {
            Ok(v) => v,
            Err(_) => panic!(),
        };

        assert_eq!(shared_1.len(), 32);
        assert_eq!(shared_2.len(), 32);
        assert_eq!(shared_1, shared_2);
    }

    #[test]
    fn test_generate_public_key() {
        let result = match Secp256k1::generate_public_key(&private_key()) {
            Ok(v) => v,
            Err(_) => panic!(),
        };

        assert_eq!(
            result,
            vec![
                0x02, 0x51, 0x84, 0x22, 0x3f, 0xe8, 0x5d, 0x53, 0x20, 0x3c, 0xf9, 0xd3, 0x7f, 0x68,
                0x22, 0xe6, 0x33, 0xe8, 0xd7, 0x9f, 0x48, 0xb1, 0x32, 0xdf, 0x0b, 0x8c, 0x8a, 0x64,
                0x11, 0x41, 0xf3, 0x19, 0xb6,
            ]
        );
    }

    #[test]
    fn test_convert_public_key() {
        let public_key = match Secp256k1::generate_public_key(&private_key()) {
            Ok(v) => v,
            Err(_) => panic!(),
        };

        let result_1 = match Secp256k1::convert_public_key(&public_key, true) {
            Ok(v) => v,
            Err(_) => panic!(),
        };

        assert_eq!(
            result_1,
            vec![
                0x02, 0x51, 0x84, 0x22, 0x3f, 0xe8, 0x5d, 0x53, 0x20, 0x3c, 0xf9, 0xd3, 0x7f, 0x68,
                0x22, 0xe6, 0x33, 0xe8, 0xd7, 0x9f, 0x48, 0xb1, 0x32, 0xdf, 0x0b, 0x8c, 0x8a, 0x64,
                0x11, 0x41, 0xf3, 0x19, 0xb6,
            ]
        );

        let result_2 = match Secp256k1::convert_public_key(&public_key, false) {
            Ok(v) => v,
            Err(_) => panic!(),
        };

        assert_eq!(
            result_2,
            vec![
                0x04, 0x51, 0x84, 0x22, 0x3f, 0xe8, 0x5d, 0x53, 0x20, 0x3c, 0xf9, 0xd3, 0x7f, 0x68,
                0x22, 0xe6, 0x33, 0xe8, 0xd7, 0x9f, 0x48, 0xb1, 0x32, 0xdf, 0x0b, 0x8c, 0x8a, 0x64,
                0x11, 0x41, 0xf3, 0x19, 0xb6, 0xa3, 0x70, 0x7c, 0xa5, 0x18, 0x61, 0xe1, 0xe2, 0xde,
                0xa4, 0x3c, 0x23, 0x84, 0xf1, 0x79, 0xed, 0x44, 0xe9, 0x8c, 0x4a, 0xd0, 0x38, 0x89,
                0x21, 0xd9, 0x6a, 0x1e, 0x05, 0x93, 0x15, 0xe7, 0x54,
            ]
        );
    }

    #[test]
    fn test_ecdsa_sign() {
        let message = String::from(&message()).as_bytes().to_vec();

        let result = match Secp256k1::ecdsa_sign(&message, &private_key()) {
            Ok(v) => v,
            Err(_) => panic!(),
        };

        assert_eq!(
            result,
            vec![
                0x5c, 0xc6, 0x48, 0x2a, 0x15, 0xd8, 0x0d, 0xc0, 0xbe, 0x6d, 0xb8, 0x31, 0xad, 0x9c,
                0x4c, 0xac, 0xd9, 0x3a, 0xb3, 0x6c, 0x08, 0x8a, 0x8b, 0x3c, 0x49, 0xc5, 0xbc, 0x79,
                0x9b, 0xf1, 0xa2, 0x69, 0x3a, 0xc2, 0xa7, 0xdc, 0xd9, 0xa5, 0x16, 0x52, 0x66, 0xa2,
                0x6d, 0xe1, 0x23, 0x41, 0x98, 0xa2, 0x4d, 0xba, 0x08, 0x74, 0x87, 0x5d, 0xba, 0xc4,
                0x00, 0x70, 0x9c, 0x99, 0x3d, 0xd0, 0xf0, 0x2c
            ]
        );
    }

    #[test]
    fn test_ecdsa_verify() {
        let message = String::from(&message()).as_bytes().to_vec();

        let signature = match Secp256k1::ecdsa_sign(&message, &private_key()) {
            Ok(v) => v,
            Err(_) => panic!(),
        };

        let public_key_compressed = match Secp256k1::generate_public_key(&private_key()) {
            Ok(v) => v,
            Err(_) => panic!(),
        };

        let result_1 = match Secp256k1::ecdsa_verify(&signature, &message, &public_key_compressed) {
            Ok(v) => v,
            Err(_) => panic!(),
        };

        assert!(result_1);

        let public_key_un_compressed =
            match Secp256k1::convert_public_key(&public_key_compressed, false) {
                Ok(v) => v,
                Err(_) => panic!(),
            };

        let result_2 =
            match Secp256k1::ecdsa_verify(&signature, &message, &public_key_un_compressed) {
                Ok(v) => v,
                Err(_) => panic!(),
            };

        assert!(result_2);
    }
}
