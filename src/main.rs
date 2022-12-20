#![feature(libc)]
#![feature(once_cell)]
#![feature(const_option)]
#![feature(default_alloc_error_handler)]
#![feature(vec_into_raw_parts)]
#![feature(trivial_bounds)]

extern crate env_logger;

use actix_web::{ middleware, HttpServer, App, web };
use clap::Parser;
use config::KeyPair;
use daemonize::Daemonize;
use unid::{keyring::mnemonic::MnemonicKeyring, extension::secure_keystore::{SecureKeyStore, SecureKeyStoreType}};
use std::{fs::{File, self}, path::PathBuf, sync::{Arc, Mutex, Once}};
use dirs;

use crate::config::AppConfig;

mod unid;
mod services;
mod config;
mod controllers;

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
                inner: Arc::new(Mutex::new(AppConfig::new()))
            };

            SINGLETON = Some(Box::new(singleton))
        });

        SINGLETON.clone().unwrap()
    }
}

#[derive(Parser, Debug)]
#[clap(name = "unid-agent")]
#[clap(name = "unid-agent")]
#[clap(version, about, long_about = None)]
struct Args {
    /// Run as daemon mode
    #[clap(short, long)]
    daemonize: bool,
}

#[actix_web::main]
async fn run(sock_path: &PathBuf) -> std::io::Result<()> {
    HttpServer::new(|| {
        App::new()
            .wrap(middleware::DefaultHeaders::new().add(("x-version", "0.1.0")))
            .wrap(middleware::Compress::default())
            .wrap(middleware::Logger::default())

            // NOTE: Public Routes
            .route("/identifiers", web::post().to(controllers::public::unid_create_identifier::handler))
            .route("/identifiers/{did}", web::get().to(controllers::public::unid_find_identifier::handler))
            .route("/transfer", web::post().to(controllers::public::unid_transfer::handler))

            // NOTE: Internal (Private) Routes
            .route("/internal/verifiable-credentials", web::post().to(controllers::internal::did_generate_vc::handler))
            .route("/internal/verifiable-credentials/verify", web::post().to(controllers::internal::did_verify_vc::handler))
            .route("/internal/verifiable-presentations", web::post().to(controllers::internal::did_generate_vp::handler))
            .route("/internal/verifiable-presentations/verify", web::post().to(controllers::internal::did_verify_vp::handler))

            .route("/internal/didcomm/plaintext-messages", web::post().to(controllers::internal::didcomm_generate_plaintext::handler))
            .route("/internal/didcomm/plaintext-messages/verify", web::post().to(controllers::internal::didcomm_verify_plaintext::handler))
            .route("/internal/didcomm/signed-messages", web::post().to(controllers::internal::didcomm_generate_signed::handler))
            .route("/internal/didcomm/signed-messages/verify", web::post().to(controllers::internal::didcomm_verify_signed::handler))
            .route("/internal/didcomm/encrypted-messages", web::post().to(controllers::internal::didcomm_generate_encrypted::handler))
            .route("/internal/didcomm/encrypted-messages/verify", web::post().to(controllers::internal::didcomm_verify_encrypted::handler))
    })
    .bind_uds(&sock_path)?
    .workers(1)
    .run()
    .await
}


fn main() -> std::io::Result<()> {
    std::env::set_var("RUST_LOG", "info");
    env_logger::init();

    let config = AppConfig::new();
    match config.write() {
        Ok(()) => (),
        Err(_) => panic!(),
    };

    let home_dir = match dirs::home_dir() {
        Some(v) => v,
        None => panic!(),
    };
    let config_dir = home_dir.join(".unid");
    let runtime_dir = config_dir.clone().join("run");
    let logs_dir = config_dir.clone().join("logs");

    match fs::create_dir_all(&runtime_dir) {
        Ok(()) => (),
        Err(_) => panic!(),
    };
    match fs::create_dir_all(&logs_dir) {
        Ok(()) => (),
        Err(_) => panic!(),
    };

    let stdout = File::create(logs_dir.clone().join("unid.log")).unwrap();
    let stderr = File::create(logs_dir.clone().join("unid.err")).unwrap();
    let sock_path = runtime_dir.clone().join("unid.sock");

    let daemonize = Daemonize::new()
        .pid_file(runtime_dir.clone().join("unid.pid"))
        .working_directory(".")
        .stdout(stdout)
        .stderr(stderr);

    let args = Args::parse();

    if args.daemonize {
        match daemonize.start() {
            Ok(_) => run(&sock_path),
            Err(_) => panic!(),
        }
    } else {
        run(&sock_path)
    }
}