use crate::{
    app_config,
    config::ExtensionsRead,
    nodex::{errors::NodeXError, runtime::random::Random},
};
use std::ffi::CStr;

pub struct Trng {}

impl Trng {
    const MAX_BUFFER_LENGTH: usize = 1024;

    pub fn new() -> Trng {
        Trng {}
    }

    fn read_external(
        &self,
        extension: &ExtensionsRead,
        size: &usize,
    ) -> Result<Vec<u8>, NodeXError> {
        log::info!("Called: read_external");

        if Trng::MAX_BUFFER_LENGTH < *size {
            return Err(NodeXError {});
        }

        unsafe {
            let buffer = [0u8; Trng::MAX_BUFFER_LENGTH + 1];
            let buffer_ptr: *const i8 = buffer.as_ptr().cast();

            let lib = match libloading::Library::new(&extension.filename) {
                Ok(v) => v,
                Err(e) => {
                    log::error!("{:?}", e);
                    return Err(NodeXError {});
                }
            };

            let func: libloading::Symbol<
                unsafe extern "C" fn(buf: *const i8, bufsize: usize, size: usize) -> u32,
            > = match lib.get(extension.symbol.as_bytes()) {
                Ok(v) => v,
                Err(e) => {
                    log::error!("{:?}", e);
                    return Err(NodeXError {});
                }
            };

            let result = func(buffer_ptr, buffer.len(), *size);

            if result != 0 {
                return Err(NodeXError {});
            }

            Ok(CStr::from_ptr(buffer_ptr).to_bytes().to_vec())
        }
    }

    fn read_internal(&self, size: &usize) -> Result<Vec<u8>, NodeXError> {
        log::info!("Called: read_internal");

        Random::bytes(size)
    }

    pub fn read(&self, size: &usize) -> Result<Vec<u8>, NodeXError> {
        let config = app_config();
        let trng = match config.inner.lock() {
            Ok(config) => config.load_trng_read_sig(),
            _ => return Err(NodeXError {}),
        };

        match trng {
            Some(v) => self.read_external(&v.read, size),
            _ => self.read_internal(size),
        }
    }
}
