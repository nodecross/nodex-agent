extern crate env_logger;

use clap::Parser;
use rumqttc::{AsyncClient, MqttOptions, QoS};
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
use crate::config::ServerConfig;
use dotenv::dotenv;
use handlers::Command;

mod config;
mod controllers;
mod handlers;
mod nodex;
mod server;
mod services;

shadow!(build);

#[derive(Clone)]
pub struct SingletonAppConfig {
    inner: Arc<Mutex<AppConfig>>,
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

pub fn server_config() -> ServerConfig {
    ServerConfig::new()
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
    /// Show node ID
    #[clap(long)]
    did: bool,
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

    let server_config = server_config();

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
    let did = node_x.create_identifier().await.unwrap();

    match cli.did {
        true => {
            println!("Node ID: {}", did.did_document.id);
            return Ok(());
        }
        false => (),
    }

    let sock_path = runtime_dir.clone().join("nodex.sock");

    // NOTE: connect mqtt server
    let mqtt_host = server_config.mqtt_host();
    let mqtt_port = server_config.mqtt_port();
    let mqtt_client_id = cuid::cuid2();

    let did_id = did.did_document.id;
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

    let server = server::new_server(&sock_path, tx);
    let server_handle = server.handle();

    let shutdown_marker = Arc::new(AtomicBool::new(false));

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

    match tokio::try_join!(server_task, sender_task, receiver_task, shutdown) {
        Ok(_) => Ok(()),
        Err(e) => {
            log::error!("{:?}", e);
            panic!()
        }
    }
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
