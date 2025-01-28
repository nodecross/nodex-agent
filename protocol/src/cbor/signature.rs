use crate::did::did_repository::DidRepository;
use crate::keyring::jwk::JwkToEd25519Error;
use chrono::serde::ts_seconds;
use chrono::{DateTime, Utc};
use coset::{iana, CborSerializable, CoseError};
use ed25519_dalek::{Signature, SignatureError, Signer, SigningKey, Verifier, VerifyingKey};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use std::io::Cursor;
use validator::Validate;

#[derive(Serialize, Deserialize, PartialEq, Debug)]
pub struct Token {
    pub did: String,
    #[serde(with = "ts_seconds")]
    pub exp: DateTime<Utc>,
}

impl Token {
    pub fn new(did: impl Into<String>) -> Self {
        Self {
            did: did.into(),
            exp: Utc::now() + std::time::Duration::from_secs(3600),
        }
    }
}

#[derive(Serialize, Deserialize, Validate, Debug)]
pub struct WithToken<T> {
    pub token: Token,
    pub inner: T,
}

#[derive(Debug, thiserror::Error)]
pub enum SignMessageError {
    #[error(transparent)]
    Cbor(ciborium::ser::Error<std::io::Error>),
    #[error(transparent)]
    Signature(SignatureError),
    #[error("cose error")]
    Cose(CoseError),
}

pub fn sign_message<M: Serialize>(
    signing_key: &SigningKey,
    message: &WithToken<M>,
) -> Result<Vec<u8>, SignMessageError> {
    let mut c = Cursor::new(Vec::new());
    ciborium::into_writer(message, &mut c).map_err(SignMessageError::Cbor)?;
    let message = c.into_inner();
    let protected = coset::HeaderBuilder::new()
        .algorithm(iana::Algorithm::EdDSA)
        .build();
    let sign1 = coset::CoseSign1Builder::new()
        .protected(protected)
        .payload(message)
        .try_create_signature(b"", |pt| {
            signing_key.try_sign(pt).map(|s| s.to_bytes().into())
        })
        .map_err(SignMessageError::Signature)?
        .build();
    let sign1_data = sign1.to_vec().map_err(SignMessageError::Cose)?;
    Ok(sign1_data)
}

#[derive(Debug, thiserror::Error)]
pub enum DecodeMessageError<F: std::error::Error> {
    #[error(transparent)]
    Cbor(ciborium::de::Error<std::io::Error>),
    #[error("cose error")]
    Cose(CoseError),
    #[error("payload is empty")]
    PayloadEmpty,
    #[error("public key is empty")]
    NotFoundPubkey,
    #[error(transparent)]
    GetDidDocument(F),
    #[error(transparent)]
    GetPubkey(JwkToEd25519Error),
    #[error("expired message")]
    Expired,
    #[error("incompatible array size: {0}")]
    VecToArray(usize),
    #[error(transparent)]
    Signature(SignatureError),
}

pub async fn verify_message<M, R>(
    did_repository: &R,
    key_type: &str,
    data: &[u8],
) -> Result<WithToken<M>, DecodeMessageError<R::FindIdentifierError>>
where
    R: DidRepository,
    M: DeserializeOwned,
{
    let sign1 = coset::CoseSign1::from_slice(data).map_err(DecodeMessageError::Cose)?;
    let payload = sign1
        .payload
        .as_ref()
        .ok_or(DecodeMessageError::PayloadEmpty)?;
    let message: WithToken<M> =
        ciborium::from_reader(Cursor::new(payload)).map_err(DecodeMessageError::Cbor)?;
    let document = did_repository
        .find_identifier(&message.token.did)
        .await
        .map_err(DecodeMessageError::GetDidDocument)?
        .ok_or(DecodeMessageError::NotFoundPubkey)?
        .did_document;
    let pubkey = document
        .get_key(key_type)
        .ok_or(DecodeMessageError::NotFoundPubkey)?;
    let pubkey: VerifyingKey = pubkey.try_into().map_err(DecodeMessageError::GetPubkey)?;
    if message.token.exp < Utc::now() {
        return Err(DecodeMessageError::Expired);
    }
    sign1.verify_signature(b"", |sig, data| {
        sig.try_into()
            .map_err(|_| DecodeMessageError::VecToArray(sig.len()))
            .and_then(|sig| {
                pubkey
                    .verify(data, &Signature::from_bytes(sig))
                    .map_err(DecodeMessageError::Signature)
            })
    })?;
    Ok(message)
}
