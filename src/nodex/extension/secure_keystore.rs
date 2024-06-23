use std::{ffi::CStr, num::NonZeroU32};

use thiserror::Error;

use crate::{
    app_config,
    config::{Extension, KeyPair},
};

#[repr(C)]
enum SecureKeystoreType {
    Sign,
    Update,
    Recover,
    Encrypt,
}

#[derive(Debug)]
pub enum SecureKeyStoreType {
    Sign,
    Update,
    Recover,
    Encrypt,
}

#[derive(Error, Debug)]
pub enum SecureKeyStoreError {
    #[error("Library loading error")]
    LibraryLoadingError(#[from] libloading::Error),
    #[error("External function failed")]
    ExternalFunctionFailed(NonZeroU32),
    #[error("CStr convert failed")]
    CStrConvertFailed(#[from] std::str::Utf8Error),
    #[error("Hex decode failed")]
    HexDecodeFailed(#[from] hex::FromHexError),
    #[error("KeyPair error")]
    KeyPairError(#[from] nodex_didcomm::keyring::secp256k1::Secp256k1Error),
}

pub struct SecureKeyStore {}

impl SecureKeyStore {
    const MAX_BUFFER_LENGTH: usize = 1024;

    pub fn new() -> SecureKeyStore {
        SecureKeyStore {}
    }

    fn write_external(
        &self,
        extension: &Extension,
        key_type: &SecureKeyStoreType,
        key_pair: &KeyPair,
    ) -> Result<(), SecureKeyStoreError> {
        log::info!("Called: write_external (type: {:?})", key_type);

        unsafe {
            let encoded_secret_key = hex::encode(key_pair.get_secret_key());
            let encoded_public_key = hex::encode(key_pair.get_public_key());
            let secret_key = [encoded_secret_key.as_bytes(), b"\0"].concat();
            let public_key = [encoded_public_key.as_bytes(), b"\0"].concat();

            let secret_key_ptr: *const i8 = secret_key.as_ptr().cast();
            let public_key_ptr: *const i8 = public_key.as_ptr().cast();

            let lib = libloading::Library::new(&extension.filename)?;

            let func: libloading::Symbol<
                unsafe extern "C" fn(
                    key_type: SecureKeystoreType,
                    secret_key_buffer: *const i8,
                    public_key_buffer: *const i8,
                    secret_key_buffer_len: usize,
                    public_key_buffer_len: usize,
                ) -> u32,
            > = lib.get(extension.symbol.as_bytes())?;

            let result = match key_type {
                SecureKeyStoreType::Sign => func(
                    SecureKeystoreType::Sign,
                    secret_key_ptr,
                    public_key_ptr,
                    encoded_secret_key.len(),
                    encoded_public_key.len(),
                ),
                SecureKeyStoreType::Update => func(
                    SecureKeystoreType::Update,
                    secret_key_ptr,
                    public_key_ptr,
                    encoded_secret_key.len(),
                    encoded_public_key.len(),
                ),
                SecureKeyStoreType::Recover => func(
                    SecureKeystoreType::Recover,
                    secret_key_ptr,
                    public_key_ptr,
                    encoded_secret_key.len(),
                    encoded_public_key.len(),
                ),
                SecureKeyStoreType::Encrypt => func(
                    SecureKeystoreType::Encrypt,
                    secret_key_ptr,
                    public_key_ptr,
                    encoded_secret_key.len(),
                    encoded_public_key.len(),
                ),
            };

            if let Some(exit_status) = NonZeroU32::new(result) {
                Err(SecureKeyStoreError::ExternalFunctionFailed(exit_status))
            } else {
                Ok(())
            }
        }
    }

    fn write_internal(
        &self,
        key_type: &SecureKeyStoreType,
        key_pair: &KeyPair,
    ) -> Result<(), SecureKeyStoreError> {
        log::info!("Called: write_internal (type: {:?})", key_type);

        let config = app_config();
        let mut config = config.lock();

        match key_type {
            SecureKeyStoreType::Sign => config.save_sign_key_pair(key_pair),
            SecureKeyStoreType::Update => config.save_update_key_pair(key_pair),
            SecureKeyStoreType::Recover => config.save_recover_key_pair(key_pair),
            SecureKeyStoreType::Encrypt => config.save_encrypt_key_pair(key_pair),
        }
        .expect("Failed to save key pair");

        Ok(())
    }

    fn read_external(
        &self,
        extension: &Extension,
        key_type: &SecureKeyStoreType,
    ) -> Result<Option<KeyPair>, SecureKeyStoreError> {
        log::info!("Called: read_external (type: {:?})", key_type);

        unsafe {
            let secret_key_buffer = [0u8; SecureKeyStore::MAX_BUFFER_LENGTH + 1];
            let public_key_buffer = [0u8; SecureKeyStore::MAX_BUFFER_LENGTH + 1];

            let secret_key_buffer_ptr: *const i8 = secret_key_buffer.as_ptr().cast();
            let public_key_buffer_ptr: *const i8 = public_key_buffer.as_ptr().cast();

            let secret_key_len = 0;
            let public_key_len = 0;

            let lib = libloading::Library::new(&extension.filename)?;

            let func: libloading::Symbol<
                unsafe extern "C" fn(
                    key_type: SecureKeystoreType,
                    secret_key_buffer: *const i8,
                    public_key_buffer: *const i8,
                    secret_key_buffer_len: usize,
                    public_key_buffer_len: usize,
                    secret_key_len: *const usize,
                    public_key_len: *const usize,
                ) -> u32,
            > = lib.get(extension.symbol.as_bytes())?;

            let result = match key_type {
                SecureKeyStoreType::Sign => func(
                    SecureKeystoreType::Sign,
                    secret_key_buffer_ptr,
                    public_key_buffer_ptr,
                    secret_key_buffer.len(),
                    public_key_buffer.len(),
                    &secret_key_len,
                    &public_key_len,
                ),
                SecureKeyStoreType::Update => func(
                    SecureKeystoreType::Update,
                    secret_key_buffer_ptr,
                    public_key_buffer_ptr,
                    secret_key_buffer.len(),
                    public_key_buffer.len(),
                    &secret_key_len,
                    &public_key_len,
                ),
                SecureKeyStoreType::Recover => func(
                    SecureKeystoreType::Recover,
                    secret_key_buffer_ptr,
                    public_key_buffer_ptr,
                    secret_key_buffer.len(),
                    public_key_buffer.len(),
                    &secret_key_len,
                    &public_key_len,
                ),
                SecureKeyStoreType::Encrypt => func(
                    SecureKeystoreType::Encrypt,
                    secret_key_buffer_ptr,
                    public_key_buffer_ptr,
                    secret_key_buffer.len(),
                    public_key_buffer.len(),
                    &secret_key_len,
                    &public_key_len,
                ),
            };

            unsafe fn to_hex_string(
                buffer_ptr: *const core::ffi::c_char,
            ) -> Result<Vec<u8>, SecureKeyStoreError> {
                let str = CStr::from_ptr(buffer_ptr as *const core::ffi::c_char).to_str()?;
                Ok(hex::decode(str)?)
            }

            let secret_key = to_hex_string(secret_key_buffer_ptr as *const core::ffi::c_char)?;
            let public_key = to_hex_string(public_key_buffer_ptr as *const core::ffi::c_char)?;
            let keypair = KeyPair::new(secret_key, public_key)?;

            if let Some(exit_status) = NonZeroU32::new(result) {
                Err(SecureKeyStoreError::ExternalFunctionFailed(exit_status))
            } else {
                Ok(Some(keypair))
            }
        }
    }

    fn read_internal(&self, key_type: &SecureKeyStoreType) -> Option<KeyPair> {
        log::debug!("Called: read_internal (type: {:?})", key_type);

        let config = app_config();
        let config = config.lock();

        match key_type {
            SecureKeyStoreType::Sign => config.load_sign_key_pair(),
            SecureKeyStoreType::Update => config.load_update_key_pair(),
            SecureKeyStoreType::Recover => config.load_recovery_key_pair(),
            SecureKeyStoreType::Encrypt => config.load_encrypt_key_pair(),
        }
    }

    pub fn write(
        &self,
        key_type: &SecureKeyStoreType,
        key_pair: &KeyPair,
    ) -> Result<(), SecureKeyStoreError> {
        let extension = {
            let config = app_config();
            let config = config.lock();
            config.load_secure_keystore_write_sig()
        };

        match extension {
            Some(v) => self.write_external(&v, key_type, key_pair),
            _ => self.write_internal(key_type, key_pair),
        }
    }

    pub fn read(
        &self,
        key_type: &SecureKeyStoreType,
    ) -> Result<Option<KeyPair>, SecureKeyStoreError> {
        let extension = {
            let config = app_config();
            let config = config.lock();
            config.load_secure_keystore_read_sig()
        };

        match extension {
            Some(v) => self.read_external(&v, key_type),
            _ => Ok(self.read_internal(key_type)),
        }
    }
}
