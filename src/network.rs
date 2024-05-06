use home_config::HomeConfig;
use serde::Deserialize;
use serde::Serialize;
use std::fs::OpenOptions;
use std::io;
use std::io::Write;
use std::path::Path;
use std::{fs, sync::MutexGuard};

use std::sync::{Arc, Mutex, Once};

#[derive(Clone)]
pub struct SingletonNetworkConfig {
    inner: Arc<Mutex<Network>>,
}

impl SingletonNetworkConfig {
    pub fn lock(&self) -> MutexGuard<'_, Network> {
        self.inner.lock().unwrap()
    }
}

pub fn network_config() -> Box<SingletonNetworkConfig> {
    static mut SINGLETON: Option<Box<SingletonNetworkConfig>> = None;
    static ONCE: Once = Once::new();

    unsafe {
        ONCE.call_once(|| {
            let singleton = SingletonNetworkConfig {
                inner: Arc::new(Mutex::new(Network::new())),
            };

            SINGLETON = Some(Box::new(singleton))
        });

        SINGLETON.clone().unwrap()
    }
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(default)]
#[derive(Default)]
struct ConfigNetwork {
    pub secret_key: Option<String>,
    pub project_did: Option<String>,
    pub recipient_dids: Option<Vec<String>>,
    pub studio_endpoint: Option<String>,
    pub heartbeat: Option<u64>,
}

#[derive(Debug)]
pub struct Network {
    config: HomeConfig,
    root: ConfigNetwork,
}

impl Network {
    fn touch(path: &Path) -> io::Result<()> {
        let mut file = OpenOptions::new().create(true).write(true).open(path)?;
        file.write_all(b"{}")?;
        Ok(())
    }

    const APP_NAME: &'static str = "nodex";
    const CONFIG_FILE: &'static str = "network.json";

    fn new() -> Self {
        let config = HomeConfig::with_config_dir(Network::APP_NAME, Network::CONFIG_FILE);
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

        let root = match config.json::<ConfigNetwork>() {
            Ok(v) => v,
            Err(e) => {
                log::error!("{:?}", e);
                panic!()
            }
        };

        Network { config, root }
    }

    pub fn write(&self) {
        if let Err(e) = self.config.save_json(&self.root) {
            log::error!("{:?}", e);
            panic!()
        }
    }

    // NOTE: secret key
    pub fn get_secret_key(&self) -> Option<String> {
        self.root.secret_key.clone()
    }

    pub fn save_secret_key(&mut self, value: &str) {
        self.root.secret_key = Some(value.to_string());
        self.write();
    }

    // NOTE: project_did
    pub fn get_project_did(&self) -> Option<String> {
        self.root.project_did.clone()
    }

    pub fn save_project_did(&mut self, value: &str) {
        self.root.project_did = Some(value.to_string());
        self.write();
    }

    // NOTE: recipient_dids
    pub fn get_recipient_dids(&self) -> Option<Vec<String>> {
        self.root.recipient_dids.clone()
    }

    pub fn save_recipient_dids(&mut self, value: Vec<String>) {
        self.root.recipient_dids = Some(value);

        self.write();
    }

    // NOTE: studio_endpoint
    pub fn get_studio_endpoint(&self) -> Option<String> {
        self.root.studio_endpoint.clone()
    }

    pub fn save_studio_endpoint(&mut self, value: &str) {
        self.root.studio_endpoint = Some(value.to_string());
        self.write();
    }

    // NOTE: heartbeat
    pub fn get_heartbeat(&self) -> Option<u64> {
        self.root.heartbeat
    }

    pub fn save_heartbeat(&mut self, value: u64) {
        self.root.heartbeat = Some(value);
        self.write();
    }
}
