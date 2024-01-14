extern crate env_logger;

use clap::{Parser, Subcommand};
use config::ProxyConfig;
use controllers::public::nodex_receive::ConnectionRepository;
use rumqttc::{AsyncClient, MqttOptions, QoS};
use services::hub::Hub;
use services::nodex::NodeX;
use shadow_rs::shadow;
use std::sync::atomic::AtomicBool;
use std::{
    collections::HashMap,
    fs::{self},
    sync::{Arc, Mutex, Once},
};
use tokio::sync::mpsc;
use tokio::sync::RwLock;
use tokio::time::Duration;

use crate::config::AppConfig;
use crate::network::Network;
use crate::{config::ServerConfig, controllers::public::nodex_receive};
use dotenv::dotenv;
use handlers::Command;
use handlers::MqttClient;
use mac_address::get_mac_address;
use std::env;

mod config;
mod controllers;
mod handlers;
mod network;
mod nodex;
mod server;
mod services;

shadow!(build);

#[derive(Clone)]
pub struct SingletonAppConfig {
    inner: Arc<Mutex<AppConfig>>,
}

#[derive(Clone)]
pub struct SingletonNetworkConfig {
    inner: Arc<Mutex<Network>>,
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

pub fn server_config() -> ServerConfig {
    ServerConfig::new()
}

pub fn proxy_config() -> ProxyConfig {
    ProxyConfig::new()
}

#[derive(Parser, Debug)]
#[clap(name = "nodex-agent")]
#[clap(name = "nodex-agent")]
#[clap(
    version = shadow_rs::formatcp!("v{} ({} {})\n{} @ {}", build::PKG_VERSION, build::SHORT_COMMIT, build::BUILD_TIME_3339, build::RUST_VERSION, build::BUILD_TARGET),
    about,
    long_about = None
)]
struct Cli {
    #[clap(long)]
    config: bool,

    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Debug, Subcommand)]
enum Commands {
    #[command(about = "help for did")]
    Did {},
    #[command(about = "help for network")]
    Network {
        #[command(subcommand)]
        command: NetworkSubCommands,
    },
}

#[derive(Debug, Subcommand)]
enum NetworkSubCommands {
    #[command(about = "help for Set")]
    Set {
        #[arg(short, long)]
        key: String,
        #[arg(short, long)]
        value: String,
    },
    #[command(about = "help for Get")]
    Get {
        #[arg(short, long)]
        key: String,
    },
}

#[tokio::main]
async fn main() -> std::io::Result<()> {
    dotenv().ok();

    let cli = Cli::parse();

    std::env::set_var("RUST_LOG", "info");
    log_init();

    let hub_did_topic = "nodex/did:nodex:test:EiCW6eklabBIrkTMHFpBln7574xmZlbMakWSCNtBWcunDg";

    let config = AppConfig::new();
    match config.write() {
        Ok(()) => (),
        Err(e) => {
            log::error!("{:?}", e);
            panic!()
        }
    };

    let home_dir = match dirs::home_dir() {
        Some(v) => v,
        None => panic!(),
    };
    let config_dir = home_dir.join(".nodex");
    let runtime_dir = config_dir.clone().join("run");
    let logs_dir = config_dir.clone().join("logs");

    match fs::create_dir_all(&runtime_dir) {
        Ok(()) => (),
        Err(e) => {
            log::error!("{:?}", e);
            panic!()
        }
    };
    match fs::create_dir_all(&logs_dir) {
        Ok(()) => (),
        Err(e) => {
            log::error!("{:?}", e);
            panic!()
        }
    };

    // NOTE: generate Key Chain
    let node_x = NodeX::new();
    let device_did = node_x.create_identifier().await.unwrap();

    // NOTE: CLI
    match cli.config {
        true => {
            use_cli(cli.command, device_did.did_document.id.clone());
            return Ok(());
        }
        false => (),
    }

    // NOTE: hub initilize
    hub_initilize(device_did.did_document.id.clone()).await;
    send_device_info().await;

    let sock_path = runtime_dir.clone().join("nodex.sock");

    // NOTE: connect mqtt server
    let mqtt_host = "demo-mqtt.getnodex.io";
    let mqtt_port = 1883;
    let mqtt_client_id = cuid::cuid2();

    let did_id = device_did.did_document.id;
    let mqtt_topic = format!("nodex/{}", did_id);

    let mut mqtt_options = MqttOptions::new(&mqtt_client_id, mqtt_host, mqtt_port);
    mqtt_options.set_clean_session(true);
    mqtt_options.set_keep_alive(Duration::from_secs(5));

    let (client, eventloop) = AsyncClient::new(mqtt_options, 10);

    client
        .subscribe(hub_did_topic, QoS::ExactlyOnce)
        .await
        .unwrap();
    log::info!("subscribed: {}", hub_did_topic);

    // NOTE: booting...
    let (tx, rx) = mpsc::channel::<Command>(32);
    let db = Arc::new(RwLock::new(HashMap::<String, bool>::new()));

    let connection_repository = ConnectionRepository::new();
    let transfer_client = Box::new(MqttClient::new(tx));

    let server = server::new_server(&sock_path, transfer_client, connection_repository.clone());
    let server_handle = server.handle();

    let shutdown_marker = Arc::new(AtomicBool::new(false));

    let message_polling_task = tokio::spawn(nodex_receive::polling_task(
        Arc::clone(&shutdown_marker),
        connection_repository.clone(),
    ));

    let heartbeat_task = tokio::spawn(handlers::heartbeat::handler(
        Arc::clone(&shutdown_marker),
        connection_repository.clone(),
    ));

    let server_task = tokio::spawn(server);
    let sender_task = tokio::spawn(handlers::sender::handler(
        rx,
        client,
        Arc::clone(&db),
        mqtt_topic,
    ));
    let receiver_task = tokio::spawn(handlers::receiver::handler(
        Arc::clone(&shutdown_marker),
        eventloop,
        Arc::clone(&db),
    ));

    let shutdown = tokio::spawn(async move {
        tokio::signal::ctrl_c().await.unwrap();

        let server_stop = server_handle.stop(true);
        shutdown_marker.store(true, std::sync::atomic::Ordering::SeqCst);

        server_stop.await;
    });

    match tokio::try_join!(
        server_task,
        sender_task,
        receiver_task,
        message_polling_task,
        heartbeat_task,
        shutdown
    ) {
        Ok(_) => Ok(()),
        Err(e) => {
            log::error!("{:?}", e);
            panic!()
        }
    }
}

fn use_cli(command: Option<Commands>, did: String) {
    let mut network_config = Network::new();
    const SECRET_KEY: &str = "secret_key";
    const PROJECT_DID: &str = "project_did";

    if let Some(command) = command {
        match command {
            Commands::Did {} => {
                println!("Node ID: {}", did);
            }
            Commands::Network { command } => match command {
                NetworkSubCommands::Set { key, value } => match &*key {
                    SECRET_KEY => {
                        network_config.save_secretk_key(&value);
                        print!("Network {} is set", SECRET_KEY);
                    }
                    PROJECT_DID => {
                        network_config.save_project_did(&value);
                        print!("Network {} is set", PROJECT_DID);
                    }
                    _ => {
                        print!("key is not found");
                    }
                },
                NetworkSubCommands::Get { key } => match &*key {
                    SECRET_KEY => {
                        if let Some(v) = network_config.get_secretk_key() {
                            println!("Network {}: {}", SECRET_KEY, v);
                            return;
                        };
                        print!("Network {} is not set", SECRET_KEY);
                    }
                    PROJECT_DID => {
                        if let Some(v) = network_config.get_project_did() {
                            println!("Network {}: {}", PROJECT_DID, v);
                            return;
                        };
                        print!("Network {} is not set", PROJECT_DID);
                    }
                    _ => {
                        print!("key is not found");
                    }
                },
            },
        }
    }
}

async fn hub_initilize(my_did: String) {
    let network_config = Network::new();
    // NOTE: check network secret_key and project_did
    match network_config.get_secretk_key() {
        Some(_) => (),
        None => {
            log::error!("Network secret_key is not set. Please set secret_key use cli");
            panic!()
        }
    }
    match network_config.get_project_did() {
        Some(_) => (),
        None => {
            log::error!("Network project_did is not set. Please set project_did use cli");
            panic!()
        }
    }

    // NOTE: register device
    let hub = Hub::new();
    match hub
        .register_device(my_did, network_config.get_project_did().unwrap())
        .await
    {
        Ok(()) => (),
        Err(e) => {
            log::error!("{:?}", e);
            panic!()
        }
    };
}

async fn send_device_info() {
    const VERSION: &str = env!("CARGO_PKG_VERSION");
    const OS: &str = env::consts::OS;
    let mac_address: String = match get_mac_address() {
        Ok(Some(ma)) => ma.to_string(),
        _ => String::from("No MAC address found."),
    };

    let network = Network::new();
    let hub = Hub::new();
    match hub
        .send_device_info(
            network.root.project_did.expect("Failed to get project_did"),
            mac_address,
            VERSION.to_string(),
            OS.to_string(),
        )
        .await
    {
        Ok(()) => (),
        Err(e) => {
            log::error!("{:?}", e);
            panic!()
        }
    };
}

use env_logger::fmt::Color;
use log::Level;

fn log_init() {
    let mut builder = env_logger::Builder::from_default_env();
    builder.format(|buf, record| {
        let level_color = match record.level() {
            Level::Trace => Color::White,
            Level::Debug => Color::Blue,
            Level::Info => Color::Green,
            Level::Warn => Color::Yellow,
            Level::Error => Color::Red,
        };
        let mut level_style = buf.style();
        level_style.set_color(level_color);

        use std::io::Write;
        writeln!(
            buf,
            "{} [{}] - {} - {} - {}:{}",
            chrono::Local::now().format("%Y-%m-%dT%H:%M:%S"),
            level_style.value(record.level()),
            record.target(),
            record.args(),
            record.file().unwrap_or(""),
            record.line().unwrap_or(0),
        )
    });
    builder.init();
}
