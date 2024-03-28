extern crate env_logger;

use crate::{config::ServerConfig, controllers::public::nodex_receive};
use clap::{Parser, Subcommand};
use dotenvy::dotenv;
use handlers::Command;
use handlers::MqttClient;
use mac_address::get_mac_address;
use rumqttc::{AsyncClient, MqttOptions, QoS};
use services::hub::Hub;
use services::nodex::NodeX;
use shadow_rs::shadow;
use std::env;
use std::{collections::HashMap, fs, sync::Arc};
use tokio::sync::mpsc;
use tokio::sync::Notify;
use tokio::sync::RwLock;
use tokio::time::Duration;

mod config;
mod controllers;
mod handlers;
mod network;
mod nodex;
mod repository;
mod server;
mod services;
mod usecase;

pub use crate::config::app_config;
pub use crate::network::network_config;

pub fn server_config() -> ServerConfig {
    ServerConfig::new()
}

shadow!(build);

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

    {
        let config = app_config();
        let config = config.lock();
        match config.write() {
            Ok(()) => (),
            Err(e) => {
                log::error!("{:?}", e);
                panic!()
            }
        };
    }

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

    let (client, _eventloop) = AsyncClient::new(mqtt_options, 10);

    client
        .subscribe(hub_did_topic, QoS::ExactlyOnce)
        .await
        .unwrap();
    log::info!("subscribed: {}", hub_did_topic);

    // NOTE: booting...
    let (tx, rx) = mpsc::channel::<Command>(32);
    let db = Arc::new(RwLock::new(HashMap::<String, bool>::new()));

    let transfer_client = Box::new(MqttClient::new(tx));

    let server = server::new_server(&sock_path, transfer_client);
    let server_handle = server.handle();

    let shutdown_notify = Arc::new(Notify::new());

    let message_polling_task =
        tokio::spawn(nodex_receive::polling_task(Arc::clone(&shutdown_notify)));

    let server_task = tokio::spawn(server);
    let sender_task = tokio::spawn(handlers::sender::handler(
        rx,
        client,
        Arc::clone(&db),
        mqtt_topic,
    ));

    let shutdown = tokio::spawn(async move {
        handle_signals().await;

        let server_stop = server_handle.stop(true);
        shutdown_notify.notify_waiters();
        server_stop.await;

        log::info!("Agent has been successfully stopped.");
    });

    match tokio::try_join!(server_task, sender_task, message_polling_task, shutdown) {
        Ok(_) => Ok(()),
        Err(e) => {
            log::error!("{:?}", e);
            panic!()
        }
    }
}

#[cfg(unix)]
async fn handle_signals() {
    use tokio::signal::unix::{signal, SignalKind};

    let ctrl_c = tokio::signal::ctrl_c();
    let mut sigterm = signal(SignalKind::terminate()).expect("Failed to bind to SIGTERM");

    tokio::select! {
        _ = ctrl_c => {
            log::info!("Received SIGINT");
        },
        _ = sigterm.recv() => {
            log::info!("Received SIGTERM");
        },
    }
}

#[cfg(not(unix))]
async fn handle_signals() {
    tokio::signal::ctrl_c()
        .await
        .expect("Failed to listen for Ctrl+C");
    log::info!("Received Ctrl+C");
}

fn use_cli(command: Option<Commands>, did: String) {
    let network_config = crate::network_config();
    let mut network_config = network_config.lock();
    const SECRET_KEY: &str = "secret_key";
    const PROJECT_DID: &str = "project_did";

    if let Some(command) = command {
        match command {
            Commands::Did {} => {
                log::info!("Node ID: {}", did);
            }
            Commands::Network { command } => match command {
                NetworkSubCommands::Set { key, value } => match &*key {
                    SECRET_KEY => {
                        network_config.save_secret_key(&value);
                        log::info!("Network {} is set", SECRET_KEY);
                    }
                    PROJECT_DID => {
                        network_config.save_project_did(&value);
                        log::info!("Network {} is set", PROJECT_DID);
                    }
                    _ => {
                        log::info!("key is not found");
                    }
                },
                NetworkSubCommands::Get { key } => match &*key {
                    SECRET_KEY => {
                        if let Some(v) = network_config.get_secret_key() {
                            log::info!("Network {}: {}", SECRET_KEY, v);
                            return;
                        };
                        log::info!("Network {} is not set", SECRET_KEY);
                    }
                    PROJECT_DID => {
                        if let Some(v) = network_config.get_project_did() {
                            log::info!("Network {}: {}", PROJECT_DID, v);
                            return;
                        };
                        log::info!("Network {} is not set", PROJECT_DID);
                    }
                    _ => {
                        log::info!("key is not found");
                    }
                },
            },
        }
    }
}

async fn hub_initilize(my_did: String) {
    let project_did = {
        let network = network_config();
        let network_config = network.lock();

        // NOTE: check network secret_key and project_did
        match network_config.get_secret_key() {
            Some(_) => (),
            None => {
                log::error!("Network secret_key is not set. Please set secret_key use cli");
                panic!()
            }
        }
        network_config
            .get_project_did()
            .expect("Network project_did is not set. Please set project_did use cli")
    };

    // NOTE: register device
    let hub = Hub::new();
    match hub.register_device(my_did, project_did).await {
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

    let project_did = network_config()
        .lock()
        .get_project_did()
        .expect("Failed to get project_did");

    let hub = Hub::new();
    match hub
        .send_device_info(
            project_did,
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

fn log_init() {
    let mut builder = env_logger::Builder::from_default_env();
    builder.format(|buf, record| {
        use std::io::Write;
        writeln!(
            buf,
            "{} [{}] - {} - {} - {}:{}",
            chrono::Utc::now().to_rfc3339(),
            record.level(),
            record.target(),
            record.args(),
            record.file().unwrap_or(""),
            record.line().unwrap_or(0),
        )
    });
    builder.init();
}
