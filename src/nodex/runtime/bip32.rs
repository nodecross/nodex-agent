use hdwallet::{ChainPath, DefaultKeyChain, ExtendedPrivKey, ExtendedPubKey, KeyChain};
use thiserror::Error;

#[derive(Debug)]
pub struct BIP32Container {
    pub public_key: Vec<u8>,
    pub private_key: Vec<u8>,
}

pub struct BIP32 {}

#[derive(Error, Debug)]
pub enum BIP32Error {
    #[error("error in hdwallet")]
    Hdwallet(hdwallet::error::Error),
}

impl BIP32 {
    pub fn get_node(seed: &[u8], derivation_path: &str) -> Result<BIP32Container, BIP32Error> {
        let master = ExtendedPrivKey::with_seed(seed).map_err(BIP32Error::Hdwallet)?;

        let chain = DefaultKeyChain::new(master);
        let path = ChainPath::new(derivation_path);

        let (private_key, _) = chain
            .derive_private_key(path)
            .map_err(BIP32Error::Hdwallet)?;

        let public_key = ExtendedPubKey::from_private_key(&private_key);

        Ok(BIP32Container {
            private_key: private_key.private_key.secret_bytes().to_vec(),
            public_key: public_key.public_key.serialize().to_vec(),
        })
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use rstest::*;

    #[fixture]
    fn seed() -> Vec<u8> {
        vec![
            0x2d, 0xc5, 0x00, 0xab, 0xea, 0x17, 0xfe, 0x36, 0x19, 0x46, 0xd6, 0x11, 0x3a, 0xf6,
            0xbc, 0x26, 0xf4, 0x8e, 0xed, 0x90, 0x4d, 0x95, 0x27, 0xb5, 0x69, 0x18, 0xbf, 0xb5,
            0xce, 0x24, 0x42, 0x51,
        ]
    }

    #[fixture]
    fn derivation_path() -> String {
        // NOTE: Ethereum
        String::from("m/44'/60'/0'/0/0")
    }

    #[test]
    fn test_get_node() {
        let result = match BIP32::get_node(&seed(), &derivation_path()) {
            Ok(v) => v,
            Err(_) => panic!(),
        };

        assert_eq!(
            result.private_key,
            vec![
                0xc8, 0x05, 0x4c, 0xe7, 0x85, 0x6e, 0x13, 0x9a, 0xab, 0xec, 0x36, 0x5f, 0x6b, 0xe4,
                0xf1, 0x1b, 0x51, 0x50, 0xb2, 0xd7, 0x6c, 0x6b, 0xb4, 0xf0, 0x05, 0xfd, 0x0b, 0x1e,
                0x0b, 0x5c, 0x92, 0x87,
            ]
        );
        assert_eq!(
            result.public_key,
            vec![
                0x02, 0x67, 0xfe, 0x57, 0xf7, 0x1e, 0xdb, 0x76, 0x60, 0x96, 0x99, 0x35, 0x0f, 0x5b,
                0x29, 0x75, 0xba, 0x6e, 0xf9, 0x00, 0x6e, 0x65, 0x27, 0xf2, 0xe4, 0xfb, 0xad, 0x41,
                0xd3, 0x74, 0xf0, 0x4f, 0x3a,
            ]
        );
    }
}
