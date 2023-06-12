use home_config::HomeConfig;
use serde::Deserialize;
use serde::Serialize;
use std::env;

use crate::nodex::errors::NodeXError;

#[derive(Debug, Serialize, Deserialize)]
pub struct Settings {
    pub extensions: Extensions,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Extensions {
    pub trng: Option<Trng>,
    pub keyrings: Option<Keyrings>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Trng {
    pub read: ExtensionsRead,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Keyrings {
    pub read: ExtensionsRead,
    pub write: ExtensionsWrite,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ExtensionsRead {
    pub filename: String,
    pub symbol: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ExtensionsWrite {
    pub filename: String,
    pub symbol: String,
}

#[derive(Debug, Serialize, Deserialize, Default)]
pub struct Credentials {
    pub credentials: CredentialsConfig,
}

#[derive(Debug, Serialize, Deserialize, Default)]
pub struct CredentialsConfig {
    pub did: Option<String>,
    pub client_id: Option<String>,
    pub client_secret: Option<String>,
}

pub struct KeyPair {
    pub public_key: Vec<u8>,
    pub private_key: Vec<u8>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
struct KeyPairConfig {
    public_key: String,
    private_key: String,
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

#[derive(Debug, Deserialize, Serialize)]
#[serde(default)]
pub struct Config {
    keyrings: KeyPairsConfig,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            keyrings: KeyPairsConfig {
                sign: None,
                update: None,
                recover: None,
                encrypt: None,
            },
        }
    }
}

#[derive(Debug)]
pub struct AppConfig {
    config: Config,
    settings: HomeConfig,
    credentials: HomeConfig,
    keyrings: HomeConfig,
}

impl AppConfig {
    pub fn new() -> Self {
        let settings = HomeConfig::with_config_dir("nodex", "settings");
        let credentials = HomeConfig::with_config_dir("nodex", "credentials");
        let keyrings = HomeConfig::with_config_dir("nodex", "keyrings");

        let config: Config = Config::default();

        AppConfig {
            config,
            settings,
            credentials,
            keyrings,
        }
    }

    pub fn write(&self) -> Result<(), NodeXError> {
        match self.keyrings.save_toml(&self.config) {
            Ok(_) => {}
            Err(e) => {
                log::error!("{:?}", e);
                panic!()
            }
        }
        if !self.credentials.path().exists() {
            match self.credentials.save_toml(Credentials::default()) {
                Ok(_) => {}
                Err(e) => {
                    log::error!("{:?}", e);
                    panic!()
                }
            }
        }
        Ok(())
    }

    pub fn encode(&self, value: &Option<Vec<u8>>) -> Option<String> {
        value.as_ref().map(hex::encode)
    }

    pub fn decode(&self, value: &Option<String>) -> Option<Vec<u8>> {
        match value {
            Some(v) => match hex::decode(v) {
                Ok(v) => Some(v),
                Err(e) => {
                    log::error!("{:?}", e);
                    None
                }
            },
            None => None,
        }
    }

    // NOTE: trng - read
    pub fn load_trng_read_sig(&self) -> Option<Trng> {
        match self.settings.toml::<Settings>() {
            Ok(v) => v.extensions.trng,
            Err(_) => None,
        }
    }

    // NOTE: secure_keystore - write
    pub fn load_secure_keystore_write_sig(&self) -> Option<ExtensionsWrite> {
        match self.settings.toml::<Settings>() {
            Ok(v) => {
                if let Some(keyring) = v.extensions.keyrings {
                    Some(keyring.write)
                } else {
                    None
                }
            }
            Err(_) => None,
        }
    }

    // NOTE: secure_keystore - read
    pub fn load_secure_keystore_read_sig(&self) -> Option<ExtensionsRead> {
        match self.settings.toml::<Settings>() {
            Ok(v) => {
                if let Some(keyring) = v.extensions.keyrings {
                    Some(keyring.read)
                } else {
                    None
                }
            }
            Err(_) => None,
        }
    }

    // NOTE: SIGN
    pub fn load_sign_key_pair(&self) -> Option<KeyPair> {
        match self.config.keyrings.sign.clone() {
            Some(v) => {
                let pk = match self.decode(&Some(v.public_key)) {
                    Some(v) => v,
                    None => return None,
                };
                let sk = match self.decode(&Some(v.private_key)) {
                    Some(v) => v,
                    None => return None,
                };

                Some(KeyPair {
                    public_key: pk,
                    private_key: sk,
                })
            }
            None => None,
        }
    }

    pub fn save_sign_key_pair(&mut self, value: &KeyPair) -> Result<(), NodeXError> {
        let pk = match self.encode(&Some(value.public_key.clone())) {
            Some(v) => v,
            None => return Err(NodeXError {}),
        };
        let sk = match self.encode(&Some(value.private_key.clone())) {
            Some(v) => v,
            None => return Err(NodeXError {}),
        };

        self.config.keyrings.sign = Some(KeyPairConfig {
            public_key: pk,
            private_key: sk,
        });

        match self.write() {
            Ok(_) => Ok(()),
            Err(e) => {
                log::error!("{:?}", e);
                panic!()
            }
        }
    }

    // NOTE: UPDATE
    pub fn load_update_key_pair(&self) -> Option<KeyPair> {
        match self.config.keyrings.update.clone() {
            Some(v) => {
                let pk = match self.decode(&Some(v.public_key)) {
                    Some(v) => v,
                    None => return None,
                };
                let sk = match self.decode(&Some(v.private_key)) {
                    Some(v) => v,
                    None => return None,
                };

                Some(KeyPair {
                    public_key: pk,
                    private_key: sk,
                })
            }
            None => None,
        }
    }

    pub fn save_update_key_pair(&mut self, value: &KeyPair) -> Result<(), NodeXError> {
        let pk = match self.encode(&Some(value.public_key.clone())) {
            Some(v) => v,
            None => return Err(NodeXError {}),
        };
        let sk = match self.encode(&Some(value.private_key.clone())) {
            Some(v) => v,
            None => return Err(NodeXError {}),
        };

        self.config.keyrings.update = Some(KeyPairConfig {
            public_key: pk,
            private_key: sk,
        });

        match self.write() {
            Ok(_) => Ok(()),
            Err(e) => {
                log::error!("{:?}", e);
                panic!()
            }
        }
    }

    // NOTE: RECOVER
    pub fn load_recovery_key_pair(&self) -> Option<KeyPair> {
        match self.config.keyrings.recover.clone() {
            Some(v) => {
                let pk = match self.decode(&Some(v.public_key)) {
                    Some(v) => v,
                    None => return None,
                };
                let sk = match self.decode(&Some(v.private_key)) {
                    Some(v) => v,
                    None => return None,
                };

                Some(KeyPair {
                    public_key: pk,
                    private_key: sk,
                })
            }
            None => None,
        }
    }

    pub fn save_recover_key_pair(&mut self, value: &KeyPair) -> Result<(), NodeXError> {
        let pk = match self.encode(&Some(value.public_key.clone())) {
            Some(v) => v,
            None => return Err(NodeXError {}),
        };
        let sk = match self.encode(&Some(value.private_key.clone())) {
            Some(v) => v,
            None => return Err(NodeXError {}),
        };

        self.config.keyrings.recover = Some(KeyPairConfig {
            public_key: pk,
            private_key: sk,
        });

        match self.write() {
            Ok(_) => Ok(()),
            Err(e) => {
                log::error!("{:?}", e);
                panic!()
            }
        }
    }

    // NOTE: ENCRYPT
    pub fn load_encrypt_key_pair(&self) -> Option<KeyPair> {
        match self.config.keyrings.encrypt.clone() {
            Some(v) => {
                let pk = match self.decode(&Some(v.public_key)) {
                    Some(v) => v,
                    None => return None,
                };
                let sk = match self.decode(&Some(v.private_key)) {
                    Some(v) => v,
                    None => return None,
                };

                Some(KeyPair {
                    public_key: pk,
                    private_key: sk,
                })
            }
            None => None,
        }
    }

    pub fn save_encrypt_key_pair(&mut self, value: &KeyPair) -> Result<(), NodeXError> {
        let pk = match self.encode(&Some(value.public_key.clone())) {
            Some(v) => v,
            None => return Err(NodeXError {}),
        };
        let sk = match self.encode(&Some(value.private_key.clone())) {
            Some(v) => v,
            None => return Err(NodeXError {}),
        };

        self.config.keyrings.encrypt = Some(KeyPairConfig {
            public_key: pk,
            private_key: sk,
        });

        match self.write() {
            Ok(_) => Ok(()),
            Err(e) => {
                log::error!("{:?}", e);
                panic!()
            }
        }
    }

    // NOTE: DID
    pub fn get_did(&self) -> Option<String> {
        match self.credentials.toml::<Credentials>() {
            Ok(v) => v.credentials.did,
            Err(_) => None,
        }
    }

    pub fn save_did(&mut self, value: &str) {
        let mut creds: Credentials;
        match self.credentials.toml::<Credentials>() {
            Ok(v) => {
                creds = v;
                creds.credentials.did = Some(value.to_string());
            }
            Err(e) => {
                log::error!("{:?}", e);
                panic!()
            }
        }
        match self.credentials.save_toml(&creds) {
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
    mqtt_host: String,
    mqtt_port: u16,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self::new()
    }
}

impl ServerConfig {
    pub fn new() -> ServerConfig {
        let endpoint =
            env::var("NODEX_DID_HTTP_ENDPOINT").unwrap_or("https://did.nodecross.io".to_string());
        let link =
            env::var("NODEX_DID_ATTACHMENT_LINK").unwrap_or("https://did.getnodex.io".to_string());
        let mqtt_host = env::var("NODEX_MQTT_HOST").unwrap_or("demo-mqtt.getnodex.io".to_string());
        let mqtt_port = env::var("NODEX_MQTT_PORT").unwrap_or("1883".to_string());
        ServerConfig {
            did_http_endpoint: endpoint,
            did_attachment_link: link,
            mqtt_host,
            mqtt_port: mqtt_port.parse::<u16>().unwrap(),
        }
    }
    pub fn did_http_endpoint(&self) -> String {
        self.did_http_endpoint.clone()
    }
    pub fn did_attachment_link(&self) -> String {
        self.did_attachment_link.clone()
    }
    pub fn mqtt_host(&self) -> String {
        self.mqtt_host.clone()
    }
    pub fn mqtt_port(&self) -> u16 {
        self.mqtt_port
    }
}
