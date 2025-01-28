use home_config::HomeConfig;
use protocol::keyring::keypair::{
    Ed25519KeyPair, K256KeyPair, KeyPair, KeyPairHex, KeyPairing, KeyPairingError, X25519KeyPair,
};
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

use crate::nodex::utils::UnwrapLog;

#[derive(Clone, Deserialize, Serialize)]
struct KeyPairsConfig {
    sign: Option<KeyPairHex>,
    sign_metrics: Option<KeyPairHex>,
    update: Option<KeyPairHex>,
    recovery: Option<KeyPairHex>,
    encrypt: Option<KeyPairHex>,
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

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct DidCommConfig {
    pub http_body_size_limit: usize,
}

#[derive(Deserialize, Serialize)]
#[serde(default)]
pub struct ConfigRoot {
    did: Option<String>,
    key_pairs: KeyPairsConfig,
    extensions: ExtensionsConfig,
    metrics: MetricsConfig,
    didcomm: DidCommConfig,
    is_initialized: bool,
    schema_version: u8,
}

impl Default for ConfigRoot {
    fn default() -> Self {
        ConfigRoot {
            did: None,
            key_pairs: KeyPairsConfig {
                sign: None,
                sign_metrics: None,
                update: None,
                recovery: None,
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
                cache_capacity: 1 << 16,
            },
            didcomm: DidCommConfig {
                http_body_size_limit: 3 * 1024 * 1024,
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

#[allow(static_mut_refs)]
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

pub struct AppConfig {
    config: HomeConfig,
    root: ConfigRoot,
}

#[derive(Error, Debug)]
pub enum AppConfigError<E: std::error::Error> {
    #[error("key decode failed")]
    DecodeFailed(E),
    #[error("failed to write config file")]
    WriteError(home_config::JsonError),
}

fn convert_to_key<U, V, T: KeyPair<U, V>>(
    config: &KeyPairHex,
) -> Result<T, AppConfigError<T::Error>> {
    T::from_hex_key_pair(config).map_err(AppConfigError::DecodeFailed)
}

#[inline]
fn load_key_pair<U, V, T: KeyPair<U, V>>(kind: &Option<KeyPairHex>) -> Option<T> {
    kind.as_ref()
        .and_then(|key| convert_to_key(key).map_err(|e| log::error!("{:?}", e)).ok())
}

impl AppConfig {
    fn touch(path: &Path) -> io::Result<()> {
        let mut file = OpenOptions::new()
            .truncate(true)
            .create(true)
            .write(true)
            .open(path)?;
        file.write_all(b"{}")?;
        Ok(())
    }

    const APP_NAME: &'static str = "nodex";
    const CONFIG_FILE: &'static str = "config.json";

    fn new() -> Self {
        let config = HomeConfig::with_config_dir(AppConfig::APP_NAME, AppConfig::CONFIG_FILE);
        let config_dir = config.path().parent().unwrap();

        if !Path::exists(config.path()) {
            fs::create_dir_all(config_dir).unwrap_log();
            Self::touch(config.path()).unwrap_log();
        }

        let root = config.json::<ConfigRoot>().unwrap_log();

        AppConfig { root, config }
    }

    pub fn write(&self) -> Result<(), AppConfigError<KeyPairingError>> {
        self.config
            .save_json(&self.root)
            .map_err(AppConfigError::WriteError)
    }

    pub fn load_sign_metrics_key_pair(&self) -> Option<Ed25519KeyPair> {
        load_key_pair(&self.root.key_pairs.sign_metrics)
    }

    pub fn save_sign_metrics_key_pair(&mut self, value: &Ed25519KeyPair) {
        self.root.key_pairs.sign_metrics = Some(value.to_hex_key_pair());
        self.write().unwrap();
    }

    pub fn load_sign_key_pair(&self) -> Option<K256KeyPair> {
        load_key_pair(&self.root.key_pairs.sign)
    }

    pub fn load_keyring(&self) -> Option<KeyPairing> {
        let sign = self.load_sign_key_pair()?;
        let sign_metrics = self.load_sign_metrics_key_pair()?;
        let update = self.load_update_key_pair()?;
        let recovery = self.load_recovery_key_pair()?;
        let encrypt = self.load_encrypt_key_pair()?;
        Some(KeyPairing {
            sign,
            sign_metrics,
            update,
            recovery,
            encrypt,
        })
    }

    pub fn save_sign_key_pair(&mut self, value: &K256KeyPair) {
        self.root.key_pairs.sign = Some(value.to_hex_key_pair());
        self.write().unwrap();
    }

    pub fn load_update_key_pair(&self) -> Option<K256KeyPair> {
        load_key_pair(&self.root.key_pairs.update)
    }

    pub fn save_update_key_pair(&mut self, value: &K256KeyPair) {
        self.root.key_pairs.update = Some(value.to_hex_key_pair());
        self.write().unwrap();
    }

    pub fn load_recovery_key_pair(&self) -> Option<K256KeyPair> {
        load_key_pair(&self.root.key_pairs.recovery)
    }

    pub fn save_recovery_key_pair(&mut self, value: &K256KeyPair) {
        self.root.key_pairs.recovery = Some(value.to_hex_key_pair());
        self.write().unwrap();
    }

    pub fn load_encrypt_key_pair(&self) -> Option<X25519KeyPair> {
        load_key_pair(&self.root.key_pairs.encrypt)
    }

    pub fn save_encrypt_key_pair(&mut self, value: &X25519KeyPair) {
        self.root.key_pairs.encrypt = Some(value.to_hex_key_pair());
        self.write().unwrap();
    }

    pub fn get_did(&self) -> Option<String> {
        self.root.did.clone()
    }

    pub fn save_did(&mut self, value: &str) {
        self.root.did = Some(value.to_string());
        self.write().unwrap_log()
    }

    pub fn get_didcomm_body_size(&self) -> usize {
        self.root.didcomm.http_body_size_limit
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

    pub fn get_metric_cache_capacity(&self) -> usize {
        let cache_capacity = self.root.metrics.clone().cache_capacity;
        if !(10_000..=1_000_000).contains(&cache_capacity) {
            log::error!("cache_capacity must be between 10_000 and 1_000_000");
            panic!()
        }
        cache_capacity
    }

    #[allow(dead_code)]
    pub fn get_is_initialized(&self) -> bool {
        self.root.is_initialized
    }

    pub fn save_is_initialized(&mut self, value: bool) {
        self.root.is_initialized = value;
        self.write().unwrap_log()
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

pub fn server_config() -> ServerConfig {
    ServerConfig::new()
}

#[derive(Debug, Clone, Deserialize, Serialize)]
struct MetricsConfig {
    collect_interval: u64,
    send_interval: u64,
    cache_capacity: usize,
}
