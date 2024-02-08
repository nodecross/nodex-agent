use crate::nodex::{
    cipher::credential_signer::{CredentialSigner, CredentialSignerSuite},
    keyring::{self},
    schema::general::{CredentialSubject, GeneralVcDataModel, Issuer},
};
use anyhow::Context;
use chrono::{DateTime, Utc};
use serde_json::{json, Value};

pub struct DIDVCService {}

impl DIDVCService {
    pub fn generate(message: &Value, issuance_date: DateTime<Utc>) -> anyhow::Result<Value> {
        let keyring = keyring::keypair::KeyPairing::load_keyring()?;
        let did = keyring.get_identifier()?;

        let r#type = "VerifiableCredential".to_string();
        let context = "https://www.w3.org/2018/credentials/v1".to_string();
        let issuance_date = issuance_date.to_rfc3339();

        let model = GeneralVcDataModel {
            id: None,
            issuer: Issuer { id: did.clone() },
            r#type: vec![r#type],
            context: vec![context],
            issuance_date,
            credential_subject: CredentialSubject {
                id: None,
                container: message.clone(),
            },
            expiration_date: None,
            proof: None,
        };

        let signed = CredentialSigner::sign(
            &model,
            &CredentialSignerSuite {
                did: Some(did),
                key_id: Some("signingKey".to_string()),
                context: keyring.get_sign_key_pair(),
            },
        )?;

        Ok(json!(signed))
    }

    pub async fn verify(message: &Value) -> anyhow::Result<Value> {
        let service = crate::services::nodex::NodeX::new();

        let model = serde_json::from_value::<GeneralVcDataModel>(message.clone())?;

        let did_document = service.find_identifier(&model.issuer.id).await?;
        let public_keys = did_document
            .did_document
            .public_key
            .ok_or(anyhow::anyhow!("public_key is not found in did_document"))?;

        // FIXME: workaround
        anyhow::ensure!(public_keys.len() == 1, "public_keys length must be 1");

        let public_key = public_keys[0].clone();
        dbg!(&public_key);

        let context = keyring::secp256k1::Secp256k1::from_jwk(&public_key.public_key_jwk)?;
        dbg!(&context);

        let (verified_model, verified) = CredentialSigner::verify(
            &model,
            &CredentialSignerSuite {
                did: None,
                key_id: None,
                context,
            },
        )
        .context("failed to verify credential")?;

        anyhow::ensure!(verified, "signature is not verified");

        Ok(verified_model)
    }
}
