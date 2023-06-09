use clap::{Parser, Subcommand};
use home_config::HomeConfig;
use std::fs;

mod credential;
mod setting;

#[derive(Debug, Parser)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
    #[command(about = "help for init")]
    Init {},
    #[command(about = "help for settings")]
    Settings {
        #[command(subcommand)]
        command: SettingsSubCommands,
    },
    #[command(about = "help for credentials")]
    Credentials {
        #[command(subcommand)]
        command: CredentialsSubCommands,
    },
}

#[derive(Debug, Subcommand)]
enum SettingsSubCommands {
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

#[derive(Debug, Subcommand)]
enum CredentialsSubCommands {
    #[command(about = "help for Import")]
    Import {
        #[arg(short, long)]
        file: String,
    },
    #[command(about = "help for Available")]
    Available {
        #[arg(short, long)]
        key: String,
    },
}

fn main() {
    let cli = Cli::parse();

    let config_settings = HomeConfig::with_config_dir("nodex", "settings");
    let config_credentials = HomeConfig::with_config_dir("nodex", "credentials");

    match cli.command {
        Commands::Init {} => {
            // settings
            let settings = setting::Settings {
                extensions: setting::Extensions {
                    trng: None,
                    keyrings: None,
                },
            };
            match config_settings.save_toml(&settings) {
                Ok(_) => {}
                Err(e) => {
                    eprintln!("Failed to save the settings: {:?}", e);
                    return;
                }
            }

            // credentials
            let credentials = credential::Credentials {
                credentials: credential::CredentialsConfig {
                    did: None,
                    client_id: None,
                    client_secret: None,
                },
            };
            match config_credentials.save_toml(&credentials) {
                Ok(_) => {}
                Err(e) => {
                    eprintln!("Failed to save the credentials: {:?}", e);
                    return;
                }
            }
        }
        Commands::Settings { command } => match command {
            SettingsSubCommands::Set { key, value } => {
                let path = config_settings
                    .path()
                    .as_path()
                    .to_str()
                    .expect("Failed path error");
                let mut editor = setting::TomlEditor::new(path).expect("Failed open error");
                match editor.update_value(&key, &value) {
                    Ok(_) => print!("0"),
                    Err(_) => {
                        print!("1");
                        return;
                    }
                }
                match editor.save(path) {
                    Ok(_) => print!("0"),
                    Err(_) => print!("1"),
                }
            }
            SettingsSubCommands::Get { key } => {
                let path = config_settings
                    .path()
                    .as_path()
                    .to_str()
                    .expect("Failed path error");
                let editor = setting::TomlEditor::new(path).expect("Failed open error");
                match editor.get_value(&key) {
                    Ok(_) => println!("0"),
                    Err(_) => println!("1"),
                }
            }
        },
        Commands::Credentials { command } => match command {
            CredentialsSubCommands::Import { file } => {
                let data = fs::read_to_string(&file).expect("Unable to read file");
                let creds: credential::CredentialsConfig =
                    serde_json::from_str(&data).expect("Unable to parse JSON");
                let data = credential::Credentials { credentials: creds };
                match config_credentials.save_toml(&data) {
                    Ok(_) => print!("0"),
                    Err(_) => print!("1"),
                }
            }
            CredentialsSubCommands::Available { key } => {
                let path = config_credentials
                    .path()
                    .as_path()
                    .to_str()
                    .expect("Failed path error");
                let editor = setting::TomlEditor::new(path).expect("Failed open error");
                match editor.get_value(&key) {
                    Ok(_) => println!("0"),
                    Err(_) => println!("1"),
                }
            }
        },
    }
}
