use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::nodex::cipher::credential_signer::Proof;

#[derive(Debug, Serialize, Deserialize, Eq, PartialEq, Clone)]
pub struct Issuer {
    #[serde(rename = "id")]
    pub id: String,
}

#[derive(Debug, Serialize, Deserialize, Eq, PartialEq, Clone)]
pub struct CredentialSubject {
    // NOTE: 'id' property is optional.
    #[serde(rename = "id", skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,

    #[serde(rename = "container")]
    pub container: Value,
}

#[derive(Debug, Serialize, Deserialize, Eq, PartialEq, Clone)]
pub struct GeneralVcDataModel {
    // NOTE: 'id' property is optional.
    #[serde(rename = "id", skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,

    #[serde(rename = "issuer")]
    pub issuer: Issuer,

    #[serde(rename = "issuanceDate")]
    pub issuance_date: String,

    #[serde(rename = "expirationDate", skip_serializing_if = "Option::is_none")]
    pub expiration_date: Option<String>,

    #[serde(rename = "@context")]
    pub context: Vec<String>,

    #[serde(rename = "type")]
    pub r#type: Vec<String>,

    #[serde(rename = "credentialSubject")]
    pub credential_subject: CredentialSubject,

    #[serde(rename = "proof", skip_serializing_if = "Option::is_none")]
    pub proof: Option<Proof>,
}
