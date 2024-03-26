use thiserror::Error;

use crate::nodex::runtime;

pub struct Hasher {}

#[derive(Debug, Error)]
pub enum HasherError {
    #[error(transparent)]
    HmacError(#[from] runtime::hmac::HmacError),
    #[error(transparent)]
    HexDecodeError(#[from] hex::FromHexError),
}

impl Hasher {
    #[allow(dead_code)]
    pub fn digest(message: &[u8], secret: &[u8]) -> Result<String, HasherError> {
        let digest = runtime::hmac::HmacSha512::digest(secret, message)?;

        Ok(hex::encode(digest))
    }

    #[allow(dead_code)]
    pub fn verify(message: &[u8], digest: &[u8], secret: &[u8]) -> Result<bool, HasherError> {
        let digest = hex::decode(digest)?;

        Ok(runtime::hmac::HmacSha512::verify(secret, message, &digest)?)
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use rstest::*;

    #[fixture]
    fn message() -> String {
        String::from("0123456789abcdef")
    }

    #[fixture]
    fn secret() -> String {
        String::from("secret")
    }

    #[fixture]
    fn digest() -> String {
        String::from("63aa09cf68fc541786276834496e96e57d2d9b41a0cbd8ce1a9f9f9478bfd5764fc8013bf47635a64367de6385b941d67662379b97cef7c0629ee871834472a8")
    }

    #[test]
    pub fn test_digest() {
        let result = match Hasher::digest(message().as_bytes(), secret().as_bytes()) {
            Ok(v) => v,
            Err(_) => panic!(),
        };

        assert_eq!(result, digest())
    }

    #[test]
    pub fn test_verify() {
        let result = match Hasher::verify(
            message().as_bytes(),
            digest().as_bytes(),
            secret().as_bytes(),
        ) {
            Ok(v) => v,
            Err(_) => panic!(),
        };

        assert!(result)
    }
}
