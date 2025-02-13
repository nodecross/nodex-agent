use bs58;
use ed25519_dalek::*;
use multibase::Base;
use multihash::Multihash;
use sha2::{Digest, Sha256};

const SHA256: u64 = 0x12;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum CryptoError {
    #[error("Failed to generate hash")]
    FailedToGenerateHash,
    #[error("Failed to sign data")]
    FailedToSignData,
}

pub fn generate_multihash_with_base58_encode(data: &[u8]) -> Result<String, CryptoError> {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let hash = hasher.finalize();
    let wrapped_hash =
        Multihash::<32>::wrap(SHA256, &hash).map_err(|_| CryptoError::FailedToGenerateHash)?;
    Ok(bs58::encode(wrapped_hash.to_bytes()).into_string())
}

pub fn validate_hash(hash: &str) -> bool {
    match bs58::decode(hash).into_vec() {
        Ok(decoded) => match Multihash::<32>::from_bytes(&decoded) {
            Ok(multihash) => multihash.code() == SHA256,
            Err(_) => false,
        },
        Err(e) => {
            println!("Error decoding hash: {:?}", e);
            false
        }
    }
}

pub fn sign_data(data: &[u8], key: &[u8]) -> Result<String, CryptoError> {
    let sign_key =
        SigningKey::from_bytes(key.try_into().map_err(|_| CryptoError::FailedToSignData)?);
    let signature = sign_key.sign(data);
    let proof_value = multibase_encode(&signature.to_bytes());
    Ok(proof_value)
}

pub fn multibase_encode(data: &[u8]) -> String {
    multibase::encode(Base::Base58Btc, data)
}

pub fn multibase_decode(data: &str) -> Result<Vec<u8>, multibase::Error> {
    let (_, decoded) = multibase::decode(data)?;
    Ok(decoded)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_multihash_with_base58encode() {
        let data = "z6MkoSFjacZb7R82htx8n1AkpgLQWR7CA6rigsc2VH9acLuF";
        let hash = generate_multihash_with_base58_encode(data.as_bytes()).unwrap();
        assert_eq!(hash, "QmdEjpG2gwEWZAx8YjBrw7mF1iuCqgrMh8S63M7PaC1Ldr");
    }

    #[test]
    fn test_validate_hash() {
        let encoded_hash = "QmdEjpG2gwEWZAx8YjBrw7mF1iuCqgrMh8S63M7PaC1Ldr";
        assert!(validate_hash(encoded_hash));

        let invalid_hash = "QmdEjpG2gwEWZAx8YjBrw7mF1iuCqgrMh8S63M7PaC1L";
        assert!(!validate_hash(invalid_hash));

        let invalid_hash = "scid";
        assert!(!validate_hash(invalid_hash));
    }
}
