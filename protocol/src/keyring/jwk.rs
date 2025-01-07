pub use data_encoding;
use data_encoding::{DecodeError, DecodePartial, BASE64URL_NOPAD};
use k256::elliptic_curve::sec1::ToEncodedPoint;
use serde::{Deserialize, Serialize};
use std::convert::{From, Into, TryFrom, TryInto};
use thiserror::Error;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Jwk {
    #[serde(rename = "kty")]
    kty: String,
    #[serde(rename = "crv")]
    crv: String,
    #[serde(rename = "x")]
    x: String,
    #[serde(rename = "y", skip_serializing_if = "Option::is_none")]
    y: Option<String>,
}

#[derive(Error, Debug)]
pub enum JwkToK256Error {
    #[error("missing y")]
    MissingY,
    #[error("decode error")]
    Decode(DecodePartial),
    #[error("different crv")]
    DifferentCrv,
    #[error("crypt error: {0}")]
    Crypt(#[from] k256::elliptic_curve::Error),
}

#[derive(Error, Debug)]
pub enum JwkToX25519Error {
    #[error("decode error: {0:?}")]
    Decode(Option<DecodeError>),
    #[error("different crv")]
    DifferentCrv,
}

#[derive(Error, Debug)]
pub enum K256ToJwkError {
    #[error("points are invalid")]
    PointsInvalid,
}

fn decode_base64url(
    s: &str,
) -> Result<k256::elliptic_curve::FieldBytes<k256::Secp256k1>, JwkToK256Error> {
    let mut result = k256::elliptic_curve::FieldBytes::<k256::Secp256k1>::default();
    BASE64URL_NOPAD
        .decode_mut(s.as_bytes(), &mut result)
        .map_err(JwkToK256Error::Decode)?;
    Ok(result)
}

impl TryFrom<&Jwk> for k256::PublicKey {
    type Error = JwkToK256Error;

    fn try_from(value: &Jwk) -> Result<Self, Self::Error> {
        if value.crv != "secp256k1" {
            return Err(JwkToK256Error::DifferentCrv);
        }
        if let Some(y) = value.y.as_ref() {
            let x = decode_base64url(&value.x)?;
            let y = decode_base64url(&y)?;
            let pk = k256::EncodedPoint::from_affine_coordinates(&x, &y, false);
            let pk = k256::PublicKey::from_sec1_bytes(pk.as_bytes())?;
            Ok(pk)
        } else {
            Err(JwkToK256Error::MissingY)
        }
    }
}

impl TryFrom<&k256::PublicKey> for Jwk {
    type Error = K256ToJwkError;

    fn try_from(value: &k256::PublicKey) -> Result<Self, Self::Error> {
        let value = value.to_encoded_point(false);
        let kty = "EC".to_string();
        let crv = "secp256k1".to_string();
        match value.coordinates() {
            k256::elliptic_curve::sec1::Coordinates::Uncompressed { x, y } => {
                let x = BASE64URL_NOPAD.encode(x);
                let y = Some(BASE64URL_NOPAD.encode(y));
                Ok(Jwk { kty, crv, x, y })
            }
            _ => Err(K256ToJwkError::PointsInvalid),
        }
    }
}

impl TryFrom<&Jwk> for x25519_dalek::PublicKey {
    type Error = JwkToX25519Error;

    fn try_from(value: &Jwk) -> Result<Self, Self::Error> {
        if value.crv != "X25519" {
            return Err(JwkToX25519Error::DifferentCrv);
        }
        let pk = BASE64URL_NOPAD
            .decode(value.x.as_bytes())
            .map_err(|e| JwkToX25519Error::Decode(Some(e)))?;
        let pk: [u8; 32] = pk.try_into().map_err(|_| JwkToX25519Error::Decode(None))?;
        Ok(pk.into())
    }
}

impl From<&x25519_dalek::PublicKey> for Jwk {
    fn from(value: &x25519_dalek::PublicKey) -> Self {
        let x = BASE64URL_NOPAD.encode(value.as_bytes());
        let kty = "OKP".to_string();
        let crv = "X25519".to_string();
        Jwk {
            kty,
            crv,
            x,
            y: None,
        }
    }
}

#[derive(Error, Debug)]
pub enum JwkToEd25519Error {
    #[error("decode error: {0:?}")]
    Decode(Option<DecodeError>),
    #[error("different crv")]
    DifferentCrv,
    #[error("crypt error: {0}")]
    Crypt(#[from] ed25519_dalek::SignatureError),
}

impl TryFrom<&Jwk> for ed25519_dalek::VerifyingKey {
    type Error = JwkToEd25519Error;

    fn try_from(value: &Jwk) -> Result<Self, Self::Error> {
        if value.crv != "Ed25519" {
            return Err(JwkToEd25519Error::DifferentCrv);
        }
        let pk = BASE64URL_NOPAD
            .decode(value.x.as_bytes())
            .map_err(|e| JwkToEd25519Error::Decode(Some(e)))?;
        let pk: [u8; 32] = pk.try_into().map_err(|_| JwkToEd25519Error::Decode(None))?;
        Ok(ed25519_dalek::VerifyingKey::from_bytes(&pk)?)
    }
}

impl From<&ed25519_dalek::VerifyingKey> for Jwk {
    fn from(value: &ed25519_dalek::VerifyingKey) -> Self {
        let x = BASE64URL_NOPAD.encode(value.as_bytes());
        let kty = "OKP".to_string();
        let crv = "Ed25519".to_string();
        Jwk {
            kty,
            crv,
            x,
            y: None,
        }
    }
}


#[cfg(test)]
pub mod tests {
    use rand_core::OsRng;

    use super::*;

    #[test]
    pub fn x25519_enc_dec() {
        let sk = x25519_dalek::StaticSecret::random_from_rng(OsRng);
        let pk = x25519_dalek::PublicKey::from(&sk);
        let jwk: Jwk = (&pk).into();
        let _pk: x25519_dalek::PublicKey = (&jwk).try_into().unwrap();
        assert_eq!(pk, _pk);
    }

    #[test]
    pub fn k256_enc_dec() {
        let sk = k256::SecretKey::random(&mut OsRng);
        let pk = sk.public_key();
        let jwk: Jwk = (&pk).try_into().unwrap();
        let _pk: k256::PublicKey = (&jwk).try_into().unwrap();
        assert_eq!(pk, _pk);
    }
}
