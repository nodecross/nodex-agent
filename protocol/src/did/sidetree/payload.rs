use core::convert::TryInto;

use data_encoding::BASE64URL_NOPAD;
use k256::ecdsa::{signature::Signer, Signature, SigningKey};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    did::sidetree::multihash, keyring::jwk::Jwk, verifiable_credentials::jws::JwsEncodeError,
};

// TODO: Migrate Sidetree Version

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ServiceEndpoint {
    #[serde(rename = "id")]
    pub id: String,

    #[serde(rename = "type")]
    pub r#type: String,

    #[serde(rename = "serviceEndpoint")]
    pub service_endpoint: String,

    #[serde(rename = "description")]
    pub description: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DidPublicKey {
    #[serde(rename = "id")]
    pub id: String,

    #[serde(rename = "controller")]
    pub controller: String,

    #[serde(rename = "type")]
    pub r#type: String,

    #[serde(rename = "publicKeyJwk")]
    pub public_key_jwk: Jwk,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DidDocument {
    // TODO: impl parser for mixed type
    // #[serde(rename = "@context")]
    // context: String,
    #[serde(rename = "id")]
    pub id: String,

    #[serde(rename = "publicKey")]
    pub public_key: Option<Vec<DidPublicKey>>,

    #[serde(rename = "service")]
    pub service: Option<Vec<ServiceEndpoint>>,

    // TODO: impl parser for mixed type
    #[serde(rename = "authentication")]
    pub authentication: Option<Vec<String>>,
}

impl DidDocument {
    pub fn get_key(&self, key_type: &str) -> Option<&Jwk> {
        self.public_key
            .as_ref()
            .and_then(|pks| pks.into_iter().find(|pk| pk.id == key_type))
            .map(|public_key| &public_key.public_key_jwk)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PublicKeyPayload {
    #[serde(rename = "id")]
    pub id: String,

    #[serde(rename = "type")]
    pub r#type: String,

    #[serde(rename = "jwk")]
    pub jwk: Jwk,

    #[serde(rename = "purpose")]
    pub purpose: Vec<String>,
}

pub trait ToPublicKey<T: TryInto<Jwk>> {
    fn to_public_key(
        self,
        key_type: String,
        key_id: String,
        purpose: Vec<String>,
    ) -> Result<PublicKeyPayload, T::Error>;
}

impl<T> ToPublicKey<T> for T
where
    T: TryInto<Jwk>,
{
    fn to_public_key(
        self,
        key_type: String,
        key_id: String,
        purpose: Vec<String>,
    ) -> Result<PublicKeyPayload, T::Error> {
        let jwk: Jwk = self.try_into()?;
        Ok(PublicKeyPayload {
            id: key_id,
            r#type: key_type,
            jwk,
            purpose,
        })
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DidPatchDocument {
    #[serde(rename = "public_keys")]
    pub public_keys: Vec<PublicKeyPayload>,

    #[serde(rename = "service_endpoints")]
    pub service_endpoints: Vec<ServiceEndpoint>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "action")]
pub enum DidAction {
    #[serde(rename = "replace")]
    Replace { document: DidPatchDocument },
    #[serde(rename = "add-public-keys")]
    AddPublicKeys {
        #[serde(rename = "public_keys")]
        public_keys: Vec<PublicKeyPayload>,
    },
}

#[derive(Serialize, Deserialize, Debug)]
struct DidDeltaObject {
    patches: Vec<DidAction>,
    update_commitment: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct DidSuffixObject {
    delta_hash: String,
    recovery_commitment: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MethodMetadata {
    #[serde(rename = "published")]
    pub published: bool,

    #[serde(rename = "recoveryCommitment")]
    pub recovery_commitment: Option<String>,

    #[serde(rename = "updateCommitment")]
    pub update_commitment: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DidResolutionResponse {
    #[serde(rename = "@context")]
    pub context: String,

    #[serde(rename = "didDocument")]
    pub did_document: DidDocument,

    #[serde(rename = "methodMetadata")]
    pub method_metadata: MethodMetadata,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type")]
enum DidPayload {
    #[serde(rename = "create")]
    Create { delta: String, suffix_data: String },
    #[serde(rename = "update")]
    Update {
        delta: String,
        // #[serde(rename = "revealValue")]
        // reveal_value: String,
        #[serde(rename = "did_suffix")]
        did_suffix: String,
        #[serde(rename = "signed_data")]
        signed_data: String,
    },
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DidCreateResponse {
    #[serde(rename = "@context")]
    pub context: String,

    #[serde(rename = "didDocument")]
    pub did_document: DidDocument,

    #[serde(rename = "methodMetadata")]
    pub method_metadata: MethodMetadata,
}

#[derive(Debug, Error)]
pub enum DidCreatePayloadError {
    #[error(transparent)]
    SerdeJsonError(#[from] serde_json::Error),
    #[error("Failed to convert to JWK: {0}")]
    Jwk(#[from] crate::keyring::jwk::K256ToJwkError),
}

#[inline]
fn canon<T>(value: &T) -> Result<Vec<u8>, serde_json::Error>
where
    T: ?Sized + Serialize,
{
    Ok(serde_jcs::to_string(value)?.into_bytes())
}

#[inline]
fn commitment_scheme(value: &Jwk) -> Result<String, serde_json::Error> {
    Ok(multihash::double_hash_encode(&canon(value)?))
}

pub fn did_create_payload(
    replace_payload: DidPatchDocument,
    update_key: k256::PublicKey,
    recovery_key: k256::PublicKey,
) -> Result<String, DidCreatePayloadError> {
    let update_commitment = commitment_scheme(&(&update_key).try_into()?)?;
    let recovery_commitment = commitment_scheme(&(&recovery_key).try_into()?)?;
    let patch = DidAction::Replace {
        document: replace_payload,
    };
    let delta = DidDeltaObject {
        patches: vec![patch],
        update_commitment,
    };
    let delta = canon(&delta)?;
    let delta_hash = multihash::hash_encode(&delta);

    let suffix = DidSuffixObject {
        delta_hash,
        recovery_commitment,
    };
    let suffix = canon(&suffix)?;
    let encoded_delta = BASE64URL_NOPAD.encode(&delta);
    let encoded_suffix = BASE64URL_NOPAD.encode(&suffix);

    let payload = DidPayload::Create {
        delta: encoded_delta,
        suffix_data: encoded_suffix,
    };

    Ok(serde_jcs::to_string(&payload)?)
}

pub fn parse_did(did: &str) -> Option<(String, String)> {
    let ret: Vec<&str> = did.splitn(3, ':').collect();
    if ret.len() == 3 {
        Some((ret[1].to_string(), ret[2].to_string()))
    } else {
        None
    }
}

pub fn get_did_suffix(method_specific_id: &str) -> Option<String> {
    let ret: Vec<&str> = method_specific_id.splitn(2, ':').collect();
    if ret.len() == 2 || ret.len() == 1 {
        Some(ret[0].to_string())
    } else {
        None
    }
}

fn sign(
    delta_hash: String,
    old_public_key: Jwk,
    old_secret_key: &k256::SecretKey,
) -> Result<String, JwsEncodeError> {
    // NOTE: header
    let header = serde_json::json!({ "alg": "ES256K".to_string() });
    let header = serde_jcs::to_string(&header)?;
    let header = BASE64URL_NOPAD.encode(header.as_bytes());
    // NOTE: payload
    let object = serde_json::json!({"delta_hash": delta_hash, "update_key": old_public_key});
    let payload = BASE64URL_NOPAD.encode(object.to_string().as_bytes());
    // NOTE: message
    let message = [header.clone(), payload.clone()].join(".");
    let message: &[u8] = message.as_bytes();

    // NOTE: signature
    let signing_key: SigningKey = old_secret_key.into();
    let signature: Signature = signing_key.try_sign(message)?;
    let signature = BASE64URL_NOPAD.encode(&signature.to_vec());

    Ok([header, payload, signature].join("."))
}

#[derive(Debug, Error)]
pub enum DidUpdatePayloadError {
    #[error(transparent)]
    SerdeJsonError(#[from] serde_json::Error),
    #[error("Failed to convert to JWK: {0}")]
    Jwk(#[from] crate::keyring::jwk::K256ToJwkError),
    #[error("Failed to parse did")]
    DidParse,
    #[error("Failed to sign: {0}")]
    Sign(#[from] JwsEncodeError),
}

// TODO: Not yet tested because sidetree is broken.
pub fn did_update_payload(
    update_payload: Vec<DidAction>,
    my_did: &str,
    old_update: k256::PublicKey,
    old_update_secret: &k256::SecretKey,
    new_update: k256::PublicKey,
) -> Result<String, DidUpdatePayloadError> {
    let old_update: Jwk = (&old_update).try_into()?;
    let new_update = commitment_scheme(&(&new_update).try_into()?)?;
    let delta = DidDeltaObject {
        patches: update_payload,
        update_commitment: new_update,
    };
    let delta = canon(&delta)?;
    let delta_hash = multihash::hash_encode(&delta);
    let encoded_delta = BASE64URL_NOPAD.encode(&delta);
    let (_, suff) = parse_did(my_did).ok_or(DidUpdatePayloadError::DidParse)?;
    let suff = get_did_suffix(&suff).ok_or(DidUpdatePayloadError::DidParse)?;

    let payload = DidPayload::Update {
        delta: encoded_delta,
        did_suffix: suff,
        // reveal_value: multihash::hash_encode(&canon(&old_update)?),
        signed_data: sign(delta_hash, old_update, old_update_secret)?,
    };
    Ok(serde_jcs::to_string(&payload)?)
}

#[cfg(test)]
pub mod tests {
    use rand_core::OsRng;

    use super::*;
    use crate::{keyring, keyring::keypair::KeyPair};

    #[test]
    pub fn test_did_create_payload() {
        let keyring = keyring::keypair::KeyPairing::create_keyring(OsRng);
        let public = keyring
            .sign
            .get_public_key()
            .to_public_key("".to_string(), "key_id".to_string(), vec!["".to_string()])
            .unwrap();
        let update = keyring.recovery.get_public_key();
        let recovery = keyring.update.get_public_key();

        let document = DidPatchDocument {
            public_keys: vec![public],
            service_endpoints: vec![],
        };

        let _result = did_create_payload(document, update, recovery).unwrap();
    }
}
