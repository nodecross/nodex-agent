use home_config::HomeConfig;
use nodex_didcomm::keyring::keypair::KeyPairing;
use nodex_didcomm::keyring::secp256k1::Secp256k1HexKeyPair;
use serde::Deserialize;
use serde::Serialize;
use std::env;
use std::io;
use std::io::Write;
use std::path::Path;
use std::{
    fs,
    sync::{Arc, Mutex, Once},
};
use std::{fs::OpenOptions, sync::MutexGuard};
use thiserror::Error;

pub type KeyPair = nodex_didcomm::keyring::secp256k1::Secp256k1;

trait KeyPairExt {
    fn to_keypair_config(&self) -> KeyPairConfig;
}

impl KeyPairExt for KeyPair {
    fn to_keypair_config(&self) -> KeyPairConfig {
        let hex = self.to_hex_key_pair();
        KeyPairConfig {
            public_key: hex::encode(hex.public_key),
            secret_key: hex::encode(hex.secret_key),
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
struct KeyPairConfig {
    public_key: String,
    secret_key: String,
}

impl KeyPairConfig {
    fn to_keypair(&self) -> anyhow::Result<KeyPair> {
        let hex = Secp256k1HexKeyPair {
            public_key: self.public_key.clone(),
            secret_key: self.secret_key.clone(),
        };

        Ok(KeyPair::from_hex_key_pair(&hex)?)
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
struct KeyPairsConfig {
    sign: Option<KeyPairConfig>,
    update: Option<KeyPairConfig>,
    recover: Option<KeyPairConfig>,
    encrypt: Option<KeyPairConfig>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Extension {
    pub filename: String,
    pub symbol: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct TRNGExtensionConfig {
    pub read: Extension,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SecureKeystoreExtensionConfig {
    pub write: Extension,
    pub read: Extension,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct CipherExtensionConfig {
    pub encrypt: Extension,
    pub decrypt: Extension,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ExtensionsConfig {
    pub trng: Option<TRNGExtensionConfig>,
    pub secure_keystore: Option<SecureKeystoreExtensionConfig>,
    pub cipher: Option<CipherExtensionConfig>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(default)]
pub struct ConfigRoot {
    did: Option<String>,
    key_pairs: KeyPairsConfig,
    extensions: ExtensionsConfig,
    metrics: MetricsConfig,
    is_initialized: bool,
    schema_version: u8,
}

impl Default for ConfigRoot {
    fn default() -> Self {
        ConfigRoot {
            did: None,
            key_pairs: KeyPairsConfig {
                sign: None,
                update: None,
                recover: None,
                encrypt: None,
            },
            extensions: ExtensionsConfig {
                trng: None,
                secure_keystore: None,
                cipher: None,
            },
            metrics: MetricsConfig {
                collect_interval: 15,
                send_interval: 60,
            },
            is_initialized: false,
            schema_version: 1,
        }
    }
}

#[derive(Clone)]
pub struct SingletonAppConfig {
    inner: Arc<Mutex<AppConfig>>,
}

impl SingletonAppConfig {
    pub fn lock(&self) -> MutexGuard<'_, AppConfig> {
        self.inner.lock().unwrap()
    }
}

pub fn app_config() -> Box<SingletonAppConfig> {
    static mut SINGLETON: Option<Box<SingletonAppConfig>> = None;
    static ONCE: Once = Once::new();

    unsafe {
        ONCE.call_once(|| {
            let singleton = SingletonAppConfig {
                inner: Arc::new(Mutex::new(AppConfig::new())),
            };

            SINGLETON = Some(Box::new(singleton))
        });

        SINGLETON.clone().unwrap()
    }
}

#[derive(Debug)]
pub struct AppConfig {
    config: HomeConfig,
    root: ConfigRoot,
}

#[derive(Error, Debug)]
pub enum AppConfigError {
    #[error("key decode failed")]
    DecodeFailed(anyhow::Error),
    #[error("failed to write config file")]
    WriteError(home_config::JsonError),
}

impl AppConfig {
    fn touch(path: &Path) -> io::Result<()> {
        let mut file = OpenOptions::new().create(true).write(true).open(path)?;
        file.write_all(b"{}")?;
        Ok(())
    }

    const APP_NAME: &'static str = "nodex";
    const CONFIG_FILE: &'static str = "config.json";

    fn new() -> Self {
        let config = HomeConfig::with_config_dir(AppConfig::APP_NAME, AppConfig::CONFIG_FILE);
        let config_dir = config.path().parent().expect("unreachable");

        if !Path::exists(config.path()) {
            match fs::create_dir_all(config_dir) {
                Ok(_) => {}
                Err(e) => {
                    log::error!("{:?}", e);
                    panic!()
                }
            };

            match Self::touch(config.path()) {
                Ok(_) => {}
                Err(e) => {
                    log::error!("{:?}", e);
                    panic!()
                }
            };
        }

        let root = match config.json::<ConfigRoot>() {
            Ok(v) => v,
            Err(e) => {
                log::error!("{:?}", e);
                panic!()
            }
        };

        AppConfig { root, config }
    }

    pub fn write(&self) -> Result<(), AppConfigError> {
        self.config
            .save_json(&self.root)
            .map_err(AppConfigError::WriteError)
    }

    // NOTE: trng - read
    pub fn load_trng_read_sig(&self) -> Option<Extension> {
        match self.root.extensions.trng.clone() {
            Some(v) => Some(v.read),
            None => None,
        }
    }

    // NOTE: secure_keystore - write
    pub fn load_secure_keystore_write_sig(&self) -> Option<Extension> {
        match self.root.extensions.secure_keystore.clone() {
            Some(v) => Some(v.write),
            None => None,
        }
    }

    // NOTE: secure_keystore - read
    pub fn load_secure_keystore_read_sig(&self) -> Option<Extension> {
        match self.root.extensions.secure_keystore.clone() {
            Some(v) => Some(v.read),
            None => None,
        }
    }

    // NOTE: cipher - encrypt
    #[allow(dead_code)]
    pub fn load_cipher_encrypt_sig(&self) -> Option<Extension> {
        match self.root.extensions.cipher.clone() {
            Some(v) => Some(v.encrypt),
            None => None,
        }
    }

    // NOTE: cipher - decrypt
    #[allow(dead_code)]
    pub fn load_cipher_decrypt_sig(&self) -> Option<Extension> {
        match self.root.extensions.cipher.clone() {
            Some(v) => Some(v.decrypt),
            None => None,
        }
    }

    // NOTE: SIGN
    pub fn load_sign_key_pair(&self) -> Option<KeyPair> {
        if let Some(ref key) = self.root.key_pairs.sign {
            match Self::convert_to_key(key) {
                Ok(v) => Some(v),
                Err(e) => {
                    log::error!("{:?}", e);
                    None
                }
            }
        } else {
            None
        }
    }

    fn convert_to_key(config: &KeyPairConfig) -> Result<KeyPair, AppConfigError> {
        config.to_keypair().map_err(AppConfigError::DecodeFailed)
    }

    pub fn load_keyring(&self) -> Option<KeyPairing> {
        let sign = self.load_sign_key_pair()?;
        let update = self.load_update_key_pair()?;
        let recovery = self.load_recovery_key_pair()?;
        let encrypt = self.load_encrypt_key_pair()?;
        Some(KeyPairing {
            sign,
            update,
            recovery,
            encrypt,
        })
    }

    pub fn save_sign_key_pair(&mut self, value: &KeyPair) -> Result<(), AppConfigError> {
        self.root.key_pairs.sign = Some(value.to_keypair_config());
        self.write()
    }

    // NOTE: UPDATE
    pub fn load_update_key_pair(&self) -> Option<KeyPair> {
        if let Some(ref key) = self.root.key_pairs.update {
            match Self::convert_to_key(key) {
                Ok(v) => Some(v),
                Err(e) => {
                    log::error!("{:?}", e);
                    None
                }
            }
        } else {
            None
        }
    }

    pub fn save_update_key_pair(&mut self, value: &KeyPair) -> Result<(), AppConfigError> {
        self.root.key_pairs.update = Some(value.to_keypair_config());
        self.write()
    }

    // NOTE: RECOVER
    pub fn load_recovery_key_pair(&self) -> Option<KeyPair> {
        match self.root.key_pairs.recover.clone() {
            Some(v) => {
                let keypair = v.to_keypair().expect("failed to decode keypair");

                Some(keypair)
            }
            None => None,
        }
    }

    pub fn save_recover_key_pair(&mut self, value: &KeyPair) -> Result<(), AppConfigError> {
        self.root.key_pairs.recover = Some(value.to_keypair_config());
        self.write()
    }

    // NOTE: ENCRYPT
    pub fn load_encrypt_key_pair(&self) -> Option<KeyPair> {
        match self.root.key_pairs.encrypt.clone() {
            Some(v) => {
                let keypair = v.to_keypair().expect("failed to decode keypair");

                Some(keypair)
            }
            None => None,
        }
    }

    pub fn save_encrypt_key_pair(&mut self, value: &KeyPair) -> Result<(), AppConfigError> {
        self.root.key_pairs.encrypt = Some(value.to_keypair_config());
        self.write()
    }

    // NOTE: DID
    pub fn get_did(&self) -> Option<String> {
        self.root.did.clone()
    }

    pub fn save_did(&mut self, value: &str) {
        self.root.did = Some(value.to_string());

        match self.write() {
            Ok(_) => {}
            Err(e) => {
                log::error!("{:?}", e);
                panic!()
            }
        }
    }

    pub fn get_metric_collect_interval(&self) -> u64 {
        let collect_interval = self.root.metrics.clone().collect_interval;
        if !(5..=300).contains(&collect_interval) {
            log::error!("collect_interval must be between 5 and 300");
            panic!()
        }
        collect_interval
    }

    pub fn get_metric_send_interval(&self) -> u64 {
        let send_interval = self.root.metrics.clone().send_interval;
        if !(60..=3600).contains(&send_interval) {
            log::error!("send_interval must be between 60 and 3600");
            panic!()
        }
        send_interval
    }

    // NOTE: Is Initialized
    #[allow(dead_code)]
    pub fn get_is_initialized(&self) -> bool {
        self.root.is_initialized
    }

    pub fn save_is_initialized(&mut self, value: bool) {
        self.root.is_initialized = value;
        match self.write() {
            Ok(_) => {}
            Err(e) => {
                log::error!("{:?}", e);
                panic!()
            }
        }
    }
}

#[derive(Debug)]
pub struct ServerConfig {
    did_http_endpoint: String,
    did_attachment_link: String,
    studio_http_endpoint: String,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self::new()
    }
}

impl ServerConfig {
    pub fn new() -> ServerConfig {
        let did_endpoint =
            env::var("NODEX_DID_HTTP_ENDPOINT").unwrap_or("https://did.nodecross.io".to_string());
        let link =
            env::var("NODEX_DID_ATTACHMENT_LINK").unwrap_or("https://did.getnodex.io".to_string());
        let studio_endpoint = env::var("NODEX_STUDIO_HTTP_ENDPOINT")
            .unwrap_or("https://http.hub.nodecross.io".to_string());

        ServerConfig {
            did_http_endpoint: did_endpoint,
            did_attachment_link: link,
            studio_http_endpoint: studio_endpoint,
        }
    }
    pub fn did_http_endpoint(&self) -> String {
        self.did_http_endpoint.clone()
    }
    pub fn did_attachment_link(&self) -> String {
        self.did_attachment_link.clone()
    }
    pub fn studio_http_endpoint(&self) -> String {
        self.studio_http_endpoint.clone()
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
struct MetricsConfig {
    collect_interval: u64,
    send_interval: u64,
}
