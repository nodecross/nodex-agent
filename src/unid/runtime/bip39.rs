use bip39::{Mnemonic, Language};

use crate::unid::{errors::UNiDError, extension::trng::TRNG};

pub enum MnemonicType {
    Words12,
    Words15,
    Words18,
    Words21,
    Words24,
}

pub struct BIP39 {}

impl BIP39 {
    pub fn generate_mnemonic (strength: &MnemonicType) -> Result<String, UNiDError> {
        let bits = match strength {
            MnemonicType::Words12 => 128,
            MnemonicType::Words15 => 160,
            MnemonicType::Words18 => 192,
            MnemonicType::Words21 => 224,
            MnemonicType::Words24 => 256,
        };

        let trng = TRNG::new();

        let seed = match trng.read(&(bits / 8)) {
            Ok(v) => v,
            Err(_) => return Err(UNiDError{})
        };

        match Mnemonic::from_entropy_in(Language::English, &seed) {
            Ok(v) => Ok(v.to_string()),
            Err(_) => Err(UNiDError{})
        }
    }

    pub fn mnemonic_to_seed (mnemonic_string: &str, passphrase: Option<&str>) -> Result<Vec<u8>, UNiDError> {
        let mnemonic = match Mnemonic::parse_in_normalized(Language::English, &mnemonic_string) {
            Ok(v) => v,
            Err(_) => return Err(UNiDError{})
        };

        match passphrase {
            Some(v) => Ok(mnemonic.to_seed_normalized(&v).to_vec()),
            None => Ok(mnemonic.to_seed_normalized("").to_vec()),
        }
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use rstest::*;

    #[fixture]
    fn mnemonic_string() -> String {
        String::from("fiction ladder avocado latin because try length giant worry symbol sample dismiss grid traffic vicious labor risk diary theory load melody fade submit hockey")
    }

    #[fixture]
    fn passphrase() -> String {
        String::from("password")
    }

    #[test]
    fn test_generate_mnemonic_12words() {
        let result = match BIP39::generate_mnemonic(&MnemonicType::Words12) {
            Ok(v) => v,
            Err(_) => panic!()
        };

        assert_eq!(result.split(" ").count(), 12)
    }

    #[test]
    fn test_generate_mnemonic_15words() {
        let result = match BIP39::generate_mnemonic(&MnemonicType::Words15) {
            Ok(v) => v,
            Err(_) => panic!()
        };

        assert_eq!(result.split(" ").count(), 15)
    }

    #[test]
    fn test_generate_mnemonic_18words() {
        let result = match BIP39::generate_mnemonic(&MnemonicType::Words18) {
            Ok(v) => v,
            Err(_) => panic!()
        };

        assert_eq!(result.split(" ").count(), 18)
    }

    #[test]
    fn test_generate_mnemonic_21words() {
        let result = match BIP39::generate_mnemonic(&MnemonicType::Words21) {
            Ok(v) => v,
            Err(_) => panic!()
        };

        assert_eq!(result.split(" ").count(), 21)
    }

    #[test]
    fn test_generate_mnemonic_24words() {
        let result = match BIP39::generate_mnemonic(&MnemonicType::Words24) {
            Ok(v) => v,
            Err(_) => panic!()
        };

        assert_eq!(result.split(" ").count(), 24)
    }

    #[test]
    fn test_mnemonic_to_seed() {
        let result = match BIP39::mnemonic_to_seed(&mnemonic_string(), None) {
            Ok(v) => v,
            Err(_) => panic!()
        };

        assert_eq!(result, vec![
            0x94, 0x27, 0x00, 0xe6, 0xd9, 0x46, 0x84, 0xc3, 0xab, 0xe4,
            0x87, 0x7a, 0x96, 0x84, 0x6b, 0xa4, 0x96, 0xfc, 0x00, 0x95,
            0xc4, 0x4e, 0xb7, 0x56, 0x0d, 0xae, 0xf7, 0x7c, 0xdc, 0x4f,
            0xb9, 0x26, 0xf1, 0x2f, 0x63, 0x22, 0x3a, 0xac, 0xd0, 0x4c,
            0x40, 0x74, 0x72, 0x2c, 0xee, 0x9a, 0x43, 0x32, 0x66, 0xab,
            0x31, 0x51, 0x15, 0x27, 0x4f, 0xa5, 0x3e, 0x8b, 0x42, 0x07,
            0xc7, 0x42, 0xfa, 0xf7,
        ])
    }

    #[test]
    fn test_mnemonic_to_seed_with_passphrase() {
        let result = match BIP39::mnemonic_to_seed(&mnemonic_string(), Some(&passphrase())) {
            Ok(v) => v,
            Err(_) => panic!()
        };

        assert_eq!(result, vec![
            0x11, 0x7e, 0xa2, 0x8c, 0xfb, 0xd1, 0x1f, 0xfa, 0x29, 0x44,
            0xe5, 0x09, 0x7b, 0x1b, 0xeb, 0xb4, 0xfe, 0x14, 0x0e, 0xe7,
            0x82, 0xa9, 0x31, 0x08, 0x56, 0x46, 0x51, 0xfc, 0x36, 0x41,
            0x58, 0xee, 0x91, 0x6e, 0x5f, 0x7b, 0x4c, 0x03, 0x9c, 0x4d,
            0xcc, 0xe5, 0x54, 0x6b, 0xa3, 0xbf, 0xe8, 0xce, 0x2f, 0x78,
            0xe7, 0xfe, 0x93, 0x0c, 0x8b, 0x25, 0x9e, 0x38, 0x52, 0xc4,
            0x88, 0x03, 0x9b, 0x02,
        ])
    }
}