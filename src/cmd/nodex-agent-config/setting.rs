use serde::{Deserialize, Serialize};
use std::fs::File;
use std::io::{Read, Write};
use toml_edit::{value, Document};

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

pub struct TomlEditor {
    doc: Document,
}

impl TomlEditor {
    pub fn new(file_path: &str) -> std::io::Result<Self> {
        let mut file = File::open(file_path)?;
        let mut toml_str = String::new();
        file.read_to_string(&mut toml_str)?;

        let doc: Document = toml_str.parse().expect("Failed to parse the TOML file");

        Ok(Self { doc })
    }

    pub fn get_value(&self, key: &str) -> std::io::Result<String> {
        let key_parts: Vec<&str> = key.split('.').collect();
        let mut current_table = self.doc.as_table();

        for part in key_parts[..key_parts.len() - 1].iter() {
            if let Some(item) = current_table.get(part) {
                if let Some(inner_table) = item.as_table() {
                    current_table = inner_table;
                } else {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        "Invalid key path",
                    ));
                }
            } else {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    "Key not found in path",
                ));
            }
        }

        let last_key = key_parts.last().unwrap();
        if let Some(item) = current_table.get(last_key) {
            if let Some(value) = item.as_str() {
                Ok(value.to_string())
            } else {
                Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "Final key does not point to a string value",
                ))
            }
        } else {
            Err(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "Final key not found",
            ))
        }
    }

    pub fn update_value(&mut self, key: &str, new_value: &str) -> std::io::Result<()> {
        let key_parts: Vec<&str> = key.split('.').collect();
        let mut current_table = self.doc.as_table_mut();

        for part in key_parts[..key_parts.len() - 1].iter() {
            if let Some(item) = current_table.get_mut(part) {
                if let Some(inner_table) = item.as_table_mut() {
                    current_table = inner_table;
                } else {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        "Invalid key path",
                    ));
                }
            } else {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    "Key not found in path",
                ));
            }
        }

        let last_key = key_parts.last().unwrap();
        if current_table.contains_key(last_key) {
            current_table[last_key] = value(new_value);
        } else {
            return Err(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "Final key not found",
            ));
        }

        Ok(())
    }

    pub fn save(&self, file_path: &str) -> std::io::Result<()> {
        let mut file = File::create(file_path)?;
        file.write_all(self.doc.to_string().as_bytes())?;
        Ok(())
    }
}
