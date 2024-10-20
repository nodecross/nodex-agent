extern crate env_logger;

use crate::controllers::public::nodex_receive;
use anyhow::anyhow;
use clap::{Parser, Subcommand};
use dotenvy::dotenv;
use handlers::Command;
use handlers::MqttClient;
use mac_address::get_mac_address;
#[cfg(unix)]
use nix::{
    sys::signal::{kill, Signal},
    unistd::Pid,
};
use rumqttc::{AsyncClient, MqttOptions, QoS};
use services::metrics::{MetricsInMemoryCacheService, MetricsWatchService};
use services::nodex::NodeX;
use services::studio::Studio;
use shadow_rs::shadow;
use std::env;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::sync::atomic::{AtomicBool, Ordering};
use std::{collections::HashMap, fs, sync::Arc};
use sysinfo::{get_current_pid, System};
use tokio::sync::mpsc;
use tokio::sync::Notify;
use tokio::sync::RwLock;
use tokio::time::Duration;

#[cfg(windows)]
use windows::Win32::{
    Foundation::{CloseHandle, GetLastError},
    System::Threading::{OpenProcess, TerminateProcess, PROCESS_TERMINATE},
};

use nodex::utils::UnwrapLog;
use usecase::metric_usecase::MetricUsecase;

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
pub use crate::config::server_config;
pub use crate::network::network_config;

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
    kill_other_self_process();

    let studio_did_topic = "nodex/did:nodex:test:EiCW6eklabBIrkTMHFpBln7574xmZlbMakWSCNtBWcunDg";

    {
        let config = app_config();
        let config = config.lock();
        config.write().unwrap_log();
    }

    let home_dir = dirs::home_dir().unwrap();
    let config_dir = home_dir.join(".nodex");
    let logs_dir = config_dir.clone().join("logs");

    fs::create_dir_all(&logs_dir).unwrap_log();

    // NOTE: generate Key Chain
    let node_x = NodeX::new();
    let device_did = node_x.create_identifier().await.unwrap();

    if cli.config {
        use_cli(cli.command, device_did.did_document.id.clone());
        return Ok(());
    }

    studio_initialize(device_did.did_document.id.clone()).await;
    send_device_info().await;

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
        .subscribe(studio_did_topic, QoS::ExactlyOnce)
        .await
        .unwrap();
    log::info!("subscribed: {}", studio_did_topic);

    let shutdown_notify = Arc::new(Notify::new());

    let cache_repository =
        MetricsInMemoryCacheService::new(app_config().lock().get_metric_cache_capacity());
    let collect_task = {
        let mut metric_usecase = MetricUsecase::new(
            Studio::new(),
            MetricsWatchService::new(),
            app_config(),
            cache_repository.clone(),
            Arc::clone(&shutdown_notify),
        );
        tokio::spawn(async move { metric_usecase.collect_task().await })
    };

    let send_task = {
        let mut metric_usecase = MetricUsecase::new(
            Studio::new(),
            MetricsWatchService::new(),
            app_config(),
            cache_repository,
            Arc::clone(&shutdown_notify),
        );
        tokio::spawn(async move { metric_usecase.send_task().await })
    };

    // NOTE: booting...
    let (tx, rx) = mpsc::channel::<Command>(32);
    let db = Arc::new(RwLock::new(HashMap::<String, bool>::new()));

    let transfer_client = MqttClient::new(tx);

    #[cfg(unix)]
    let server = {
        let runtime_dir = config_dir.clone().join("run");
        fs::create_dir_all(&runtime_dir).unwrap_log();
        let sock_path = runtime_dir.clone().join("nodex.sock");

        let uds_server = server::new_uds_server(&sock_path, transfer_client);
        let permissions = fs::Permissions::from_mode(0o766);
        fs::set_permissions(&sock_path, permissions)?;

        uds_server
    };

    #[cfg(windows)]
    let server = {
        let port_str =
            env::var("NODEX_SERVER_PORT").expect("NODEX_SERVER_PORT must be set and valid.");
        let port = validate_port(&port_str).expect("Invalid port number.");
        server::new_web_server(port, transfer_client)
    };

    let server_handle = server.handle();

    let message_polling_task =
        tokio::spawn(nodex_receive::polling_task(Arc::clone(&shutdown_notify)));

    let server_task = tokio::spawn(server);
    let sender_task = tokio::spawn(handlers::sender::handler(
        rx,
        client,
        Arc::clone(&db),
        mqtt_topic,
    ));

    let should_stop = Arc::new(AtomicBool::new(false));
    let shutdown = tokio::spawn(async move {
        handle_signals(should_stop.clone()).await;

        let server_stop = server_handle.stop(true);
        shutdown_notify.notify_waiters();
        server_stop.await;

        log::info!("Agent has been successfully stopped.");
    });

    let _ = tokio::try_join!(
        server_task,
        sender_task,
        message_polling_task,
        collect_task,
        send_task,
        shutdown
    )
    .unwrap_log();
    Ok(())
}

#[cfg(windows)]
fn validate_port(port_str: &str) -> Result<u16, String> {
    match port_str.parse::<u16>() {
        Ok(port) if (1024..=65535).contains(&port) => Ok(port),
        _ => Err("Port number must be an integer between 1024 and 65535.".to_string()),
    }
}

#[cfg(unix)]
async fn handle_signals(should_stop: Arc<AtomicBool>) {
    use tokio::signal::unix::{signal, SignalKind};

    let ctrl_c = tokio::signal::ctrl_c();
    let mut sigterm = signal(SignalKind::terminate()).expect("Failed to bind to SIGTERM");

    tokio::select! {
        _ = ctrl_c => {
            log::info!("Received SIGINT");
            should_stop.store(true, Ordering::Relaxed);
        },
        _ = sigterm.recv() => {
            log::info!("Received SIGTERM");
            should_stop.store(true, Ordering::Relaxed);
        },
    }
}

#[cfg(windows)]
async fn handle_signals(should_stop: Arc<AtomicBool>) {
    tokio::signal::ctrl_c()
        .await
        .expect("Failed to listen for Ctrl+C");
    log::info!("Received Ctrl+C");
    should_stop.store(true, Ordering::Relaxed);
}

fn use_cli(command: Option<Commands>, did: String) {
    let network_config = crate::network_config();
    let mut network_config = network_config.lock();
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
                            println!("Network {}: {}", SECRET_KEY, v);
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

async fn studio_initialize(my_did: String) {
    let project_did = {
        let network = network_config();
        let network_config = network.lock();

        // NOTE: check network secret_key and project_did
        network_config
            .get_secret_key()
            .ok_or("Network secret_key is not set. Please set secret_key use cli")
            .unwrap_log();
        network_config
            .get_project_did()
            .expect("Network project_did is not set. Please set project_did use cli")
    };

    let studio = Studio::new();
    studio
        .register_device(my_did, project_did)
        .await
        .unwrap_log();
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

    let studio = Studio::new();
    studio
        .send_device_info(
            project_did,
            mac_address,
            VERSION.to_string(),
            OS.to_string(),
        )
        .await
        .unwrap_log();
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

fn kill_other_self_process() {
    let current_pid = get_current_pid().unwrap_log();
    let mut system = System::new_all();
    system.refresh_all();

    #[cfg(unix)]
    let process_name = { "nodex-agent" };
    #[cfg(windows)]
    let process_name = { "nodex-agent.exe" };

    for process in system.processes_by_exact_name(process_name) {
        if current_pid == process.pid() {
            continue;
        }
        if process.parent() == Some(current_pid) {
            continue;
        }

        let pid = process.pid().as_u32();
        if let Err(e) = kill_process(pid) {
            log::error!("Failed to kill process with PID: {}. Error: {:?}", pid, e);
        }
    }
}
#[cfg(unix)]
fn kill_process(pid: u32) -> Result<(), anyhow::Error> {
    kill(Pid::from_raw(pid as i32), Signal::SIGTERM).map_err(|e| {
        anyhow!(
            "Failed to kill nodex process with PID: {}. Error: {}",
            pid,
            e
        )
    })?;
    log::info!("nodex Process with PID: {} killed successfully.", pid);
    Ok(())
}

#[cfg(windows)]
fn kill_process(pid: u32) -> Result<(), anyhow::Error> {
    unsafe {
        let handle = OpenProcess(PROCESS_TERMINATE, false, pid)?;
        if handle.is_invalid() {
            return Err(anyhow!(
                "Failed to open process with PID: {}. Invalid handle.",
                pid
            ));
        }

        match TerminateProcess(handle, 1) {
            Ok(_) => {
                log::info!("nodex Process with PID: {} killed successfully.", pid);
            }
            Err(e) => {
                CloseHandle(handle);
                return Err(anyhow!(
                    "Failed to terminate process with PID: {}. Error: {:?}",
                    pid,
                    GetLastError()
                ));
            }
        };
        CloseHandle(handle);
    }

    Ok(())
}
