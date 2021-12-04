#![cfg_attr(not(test), no_std)]
#![cfg_attr(not(test), no_main)]
#![feature(libc)]
#![feature(once_cell)]
#![feature(const_option)]
#![feature(default_alloc_error_handler)]
#![feature(const_fn_fn_ptr_basics)]
#![feature(vec_into_raw_parts)]

extern crate alloc;
extern crate scrypt;
extern crate base64;

mod unid;
mod logger;
mod allocator;
mod handler;

use core::lazy::Lazy;
use alloc::string::{String, ToString};
use cstr_core::{CStr, CString, c_char};
use logger::Logger;
use spin::Mutex;
use unid::utils::data_t::DataT;
use unid::utils::aes_crypt::AesCrypt;

#[cfg_attr(not(test), global_allocator)]
static mut ALLOCATOR: allocator::ExternalHeap = allocator::ExternalHeap::empty();

static mut AES_CRYPT: AesCrypt = AesCrypt::empty();

#[repr(C)]
pub struct UNiDConfig {
    client_id: *const c_char,
    client_secret: *const c_char,
}

#[repr(C)]
pub struct UNiDContext {
    client_id: *const c_char,
    client_secret: *const c_char,
}

//
pub static mut MUTEX_HANDLERS: Lazy<Mutex<handler::UNiDHandler>> = Lazy::new(|| {
    Mutex::new(handler::UNiDHandler::new())
});

/// # Safety
#[no_mangle]
pub unsafe extern "C" fn unid_disposer(ptr: *mut c_char) {
    let _logger = Logger::new(MUTEX_HANDLERS.lock().get_debug_message_handler());

    if ptr.is_null() {
        return;
    }

    let _ = CString::from_raw(ptr);
}

/// # Safety
#[no_mangle]
pub unsafe extern "C" fn unid_regist_handler_on_memory_alloc(handler: extern "C" fn(u32) -> *mut allocator::c_void) {
    MUTEX_HANDLERS.lock().set_memory_alloc_handler(handler)
}

/// # Safety
#[no_mangle]
pub unsafe extern "C" fn unid_regist_handler_on_memory_dealloc(handler: extern "C" fn(*mut allocator::c_void)) {
    MUTEX_HANDLERS.lock().set_memory_dealloc_handler(handler)
}

/// # Safety
#[no_mangle]
pub unsafe extern "C" fn unid_regist_handler_on_debug_message(handler: extern "C" fn(u32, *mut c_char)) {
    MUTEX_HANDLERS.lock().set_debug_message_handler(handler)
}

/// unid :: init
/// 
/// # Safety
#[no_mangle]
pub unsafe extern "C" fn unid_init(config: UNiDConfig) -> UNiDContext {
    let _logger = Logger::new(MUTEX_HANDLERS.lock().get_debug_message_handler());

    let alloc_handler = MUTEX_HANDLERS.lock().get_memory_alloc_handler();
    let dealloc_handler = MUTEX_HANDLERS.lock().get_memory_dealloc_handler();

    assert!(! alloc_handler.is_none());
    assert!(! dealloc_handler.is_none());

    ALLOCATOR.init(alloc_handler.unwrap(), dealloc_handler.unwrap());

    // build context then return
    UNiDContext {
        client_id    : config.client_id,
        client_secret: config.client_secret,
    }
}

/// aes :: init
/// 
/// # Safety
#[no_mangle]
pub unsafe extern "C" fn aes_init(encryptor: extern "C" fn(*mut DataT, *mut DataT, *mut DataT, *mut u8, u32), decryptor: extern "C" fn(*mut DataT, *mut DataT, *mut DataT, *mut u8, u32)) {
    AES_CRYPT.init(encryptor, decryptor);
}

/// unid :: core :: create_did
/// 
/// # Safety
#[no_mangle]
pub unsafe extern "C" fn unid_core_create_did(_context: UNiDContext) -> *mut c_char {
    let _logger = Logger::new(MUTEX_HANDLERS.lock().get_debug_message_handler());

    let r = String::from("WIP_FOR_ROT");
    let r_c_str = CString::new(r).unwrap();

    r_c_str.into_raw()
}

/// unid :: core :: resolve_did
/// 
/// # Safety
#[no_mangle]
pub unsafe extern "C" fn unid_core_resolve_did(_context: UNiDContext) -> *mut c_char {
    let _logger = Logger::new(MUTEX_HANDLERS.lock().get_debug_message_handler());

    let r = String::from("WIP_FOR_ROT");
    let r_c_str = CString::new(r).unwrap();

    r_c_str.into_raw()
}

/// unid :: core :: update_did
/// 
/// # Safety
#[no_mangle]
pub unsafe extern "C" fn unid_core_update_did(_context: UNiDContext) -> *mut c_char {
    let _logger = Logger::new(MUTEX_HANDLERS.lock().get_debug_message_handler());

    let r = String::from("WIP_FOR_ROT");
    let r_c_str = CString::new(r).unwrap();

    r_c_str.into_raw()
}

/// unid :: core :: revoke_did
/// 
/// # Safety
#[no_mangle]
pub unsafe extern "C" fn unid_core_revoke_did(_context: UNiDContext) -> *mut c_char {
    let _logger = Logger::new(MUTEX_HANDLERS.lock().get_debug_message_handler());

    let r = String::from("WIP_FOR_ROT");
    let r_c_str = CString::new(r).unwrap();

    r_c_str.into_raw()
}

/// unid :: core :: verify_credentials
/// 
/// # Safety
#[no_mangle]
pub unsafe extern "C" fn unid_core_verify_credentials(_context: UNiDContext) -> *mut c_char {
    let _logger = Logger::new(MUTEX_HANDLERS.lock().get_debug_message_handler());

    let r = String::from("WIP_FOR_ROT");
    let r_c_str = CString::new(r).unwrap();

    r_c_str.into_raw()
}

/// unid :: core :: verify_presentations
/// 
/// # Safety
#[no_mangle]
pub unsafe extern "C" fn unid_core_verify_presentations(_context: UNiDContext) -> *mut c_char {
    let _logger = Logger::new(MUTEX_HANDLERS.lock().get_debug_message_handler());

    let r = String::from("WIP_FOR_ROT");
    let r_c_str = CString::new(r).unwrap();

    r_c_str.into_raw()
}

/// unid :: did :: create_credentials
/// 
/// # Safety
#[no_mangle]
pub unsafe extern "C" fn unid_did_create_credentials(_context: UNiDContext) -> *mut c_char {
    let _logger = Logger::new(MUTEX_HANDLERS.lock().get_debug_message_handler());

    let r = String::from("WIP_FOR_ROT");
    let r_c_str = CString::new(r).unwrap();

    r_c_str.into_raw()
}

/// unid :: did :: create_presentations
/// 
/// # Safety
#[no_mangle]
pub unsafe extern "C" fn unid_did_create_presentations(_context: UNiDContext) -> *mut c_char {
    let _logger = Logger::new(MUTEX_HANDLERS.lock().get_debug_message_handler());

    let r = String::from("WIP_FOR_ROT");
    let r_c_str = CString::new(r).unwrap();

    r_c_str.into_raw()
}

/// unid :: runtime :: bip39 :: generate_mnemonic
/// 
/// # Safety
#[no_mangle]
pub unsafe extern "C" fn unid_runtime_bip39_generate_mnemonic() -> *mut c_char {
    let _logger = Logger::new(MUTEX_HANDLERS.lock().get_debug_message_handler());

    let r = String::from("WIP_FOR_ROT");
    let r_c_str = CString::new(r).unwrap();

    r_c_str.into_raw()
}

/// unid :: utils :: random :: get_random_bytes
/// 
/// # Safety
#[no_mangle]
pub unsafe extern "C" fn unid_utils_random_get_random_bytes(_length: i32) -> *mut c_char {
    let _logger = Logger::new(MUTEX_HANDLERS.lock().get_debug_message_handler());

    let r = String::from("WIP_FOR_ROT");
    let r_c_str = CString::new(r).unwrap();

    r_c_str.into_raw()
}

/// unid :: utils :: codec :: base64_encode
/// 
/// # Safety
#[no_mangle]
pub unsafe extern "C" fn unid_utils_codec_base64_encode(content: *const c_char) -> *mut c_char {
    let _logger = Logger::new(MUTEX_HANDLERS.lock().get_debug_message_handler());

    let v1 = {
        assert!(! content.is_null());

        CStr::from_ptr(content)
    };
    let v1_str = v1.to_str().unwrap().to_string();

    let r = unid::utils::codec::Codec::base64_encode(v1_str);
    let r_c_str = CString::new(r).unwrap();

    r_c_str.into_raw()
}

/// unid :: utils :: codec :: base64_decode
/// 
/// # Safety
#[no_mangle]
pub unsafe extern "C" fn unid_utils_codec_base64_decode(content: *const c_char) -> *mut c_char {
    let _logger = Logger::new(MUTEX_HANDLERS.lock().get_debug_message_handler());

    let v1 = {
        assert!(! content.is_null());

        CStr::from_ptr(content)
    };
    let v1_str = v1.to_str().unwrap().to_string();

    let r = unid::utils::codec::Codec::base64_decode(v1_str);
    let r_c_str = CString::new(r).unwrap();

    r_c_str.into_raw()
}

/// unid :: utils :: multihasher :: hash
/// 
/// # Safety
#[no_mangle]
pub unsafe extern "C" fn unid_utils_multihasher_hash(_content: *const c_char) -> *mut c_char {
    let _logger = Logger::new(MUTEX_HANDLERS.lock().get_debug_message_handler());

    let r = String::from("WIP_FOR_ROT");
    let r_c_str = CString::new(r).unwrap();

    r_c_str.into_raw()
}

/// unid :: ciphers :: signer :: sign
/// 
/// # Safety
#[no_mangle]
pub unsafe extern "C" fn unid_ciphers_signer_sign() -> *mut c_char {
    let _logger = Logger::new(MUTEX_HANDLERS.lock().get_debug_message_handler());

    let r = String::from("WIP_FOR_ROT");
    let r_c_str = CString::new(r).unwrap();

    r_c_str.into_raw()
}

/// unid :: ciphers :: signer :: verify
/// 
/// # Safety
#[no_mangle]
pub unsafe extern "C" fn unid_ciphers_signer_verify() -> *mut c_char {
    let _logger = Logger::new(MUTEX_HANDLERS.lock().get_debug_message_handler());

    let r = String::from("WIP_FOR_ROT");
    let r_c_str = CString::new(r).unwrap();

    r_c_str.into_raw()
}

/// unid :: ciphers :: cipher :: encrypt
/// 
/// # Safety
#[no_mangle]
pub unsafe extern "C" fn unid_ciphers_cipher_encrypt(plaintext: *const c_char, secret: *const c_char) -> *mut c_char {
    let logger = Logger::new(MUTEX_HANDLERS.lock().get_debug_message_handler());

    logger.debug("(BEGIN) unid_ciphers_cipher_encrypt");

    // v1
    let v1 = {
        assert!(! plaintext.is_null());

        CStr::from_ptr(plaintext)
    };
    let v1_str = v1.to_str().unwrap().to_string();
    logger.debug(alloc::format!("v1_str = {:?}", v1_str));

    // v2
    let v2 = {
        assert!(! secret.is_null());

        CStr::from_ptr(secret)
    };
    let v2_str = v2.to_str().unwrap().to_string();
    logger.debug(alloc::format!("v2_str = {:?}", v2_str));

    // result

    let r = unid::ciphers::cipher::Cipher::encrypt(v1_str, v2_str);

    let r_c_str = CString::new(r).unwrap();
    let r_ptr = r_c_str.into_raw();

    logger.debug("( END ) unid_ciphers_cipher_encrypt");

    r_ptr
}

/// unid :: ciphers :: cipher :: decrypt
/// 
/// # Safety
#[no_mangle]
pub unsafe extern "C" fn unid_ciphers_cipher_decrypt(buffered_ciphertext_base64: *const c_char, secret: *const c_char) -> *mut c_char {
    let logger = Logger::new(MUTEX_HANDLERS.lock().get_debug_message_handler());

    logger.debug("(BEGIN) unid_ciphers_cipher_decrypt");

    // v1
    let v1 = {
        assert!(! buffered_ciphertext_base64.is_null());

        CStr::from_ptr(buffered_ciphertext_base64)
    };
    let v1_str = v1.to_str().unwrap().to_string();
    logger.debug(alloc::format!("v1_str = {:?}", v1_str));

    // v2
    let v2 = {
        assert!(! secret.is_null());

        CStr::from_ptr(secret)
    };
    let v2_str = v2.to_str().unwrap().to_string();
    logger.debug(alloc::format!("v2_str = {:?}", v2_str));

    // result

    let r = unid::ciphers::cipher::Cipher::decrypt(v1_str, v2_str);

    let r_c_str = CString::new(r).unwrap();
    let r_ptr = r_c_str.into_raw();

    logger.debug("( END ) unid_ciphers_cipher_decrypt");

    r_ptr
}

/// unid :: ciphers :: hasher :: digest
/// 
/// # Safety
#[no_mangle]
pub unsafe extern "C" fn unid_ciphers_hasher_digest(content: *const c_char, secret: *const c_char) -> *mut c_char {
    let logger = Logger::new(MUTEX_HANDLERS.lock().get_debug_message_handler());

    logger.debug("(BEGIN) unid_ciphers_hasher_digest");

    // v1
    let v1 = {
        assert!(! content.is_null());

        CStr::from_ptr(content)
    };
    let v1_str = v1.to_str().unwrap().to_string();

    // v2
    let v2 = {
        assert!(! secret.is_null());

        CStr::from_ptr(secret)
    };
    let v2_str = v2.to_str().unwrap().to_string();

    // result
    let r = unid::ciphers::hasher::Hasher::digest(v1_str, v2_str);
    let r_c_str = CString::new(r).unwrap();
    let r_ptr = r_c_str.into_raw();

    logger.debug("( END ) unid_ciphers_hasher_digest");

    r_ptr
}

/// unid :: ciphers :: hasher :: verify
/// 
/// # Safety
#[no_mangle]
pub unsafe extern "C" fn unid_ciphers_hasher_verify(content: *const c_char, digest: *const c_char, secret: *const c_char) -> bool {
    let logger = Logger::new(MUTEX_HANDLERS.lock().get_debug_message_handler());

    logger.debug("(BEGIN) unid_ciphers_hasher_verify");

    // v1
    let v1 = {
        assert!(! content.is_null());

        CStr::from_ptr(content)
    };
    let v1_str = v1.to_str().unwrap().to_string();

    // v2
    let v2 = {
        assert!(! digest.is_null());

        CStr::from_ptr(digest)
    };
    let v2_str = v2.to_str().unwrap().to_string();

    // v3
    let v3 = {
        assert!(! secret.is_null());

        CStr::from_ptr(secret)
    };
    let v3_str = v3.to_str().unwrap().to_string();

    // result
    let r_value = unid::ciphers::hasher::Hasher::verify(v1_str, v2_str, v3_str);

    logger.debug("( END ) unid_ciphers_hasher_verify");

    r_value
}

#[cfg(not(test))]
use core::panic::PanicInfo;

#[cfg(not(test))]
#[panic_handler]
pub extern "C" fn panic(_panic: &PanicInfo<'_>) -> ! {
    loop {}
}

#[cfg(test)]
mod tests {
    use super::*;

    extern crate std;

    #[cfg_attr(test, global_allocator)]
    static mut A: std::alloc::System = std::alloc::System;

    #[test]
    fn test_unid_ciphers_hasher_digest() {
        let content = CString::new("content");
        let secret = CString::new("secret");

        unsafe {
            let c_ptr = unid_ciphers_hasher_digest(content.unwrap().as_ptr(), secret.unwrap().as_ptr());
            let c_str = CStr::from_ptr(c_ptr);

            assert_eq!(
                c_str.to_str().unwrap(),
                "pfMFlg7ax3Oka6O6FiWJxyAEVels4EOHUWVIgL8YXW21G+BkA5KTxCSJGnpd7hfAsodxp0Cu2Oa2uXdwqmOmXQ=="
            );

            // dispose!
            unid_disposer(c_ptr);
        }
    }

    #[test]
    fn test_unid_ciphers_hasher_verify() {
        let content = CString::new("content");
        let secret = CString::new("secret");
        let digest = CString::new("pfMFlg7ax3Oka6O6FiWJxyAEVels4EOHUWVIgL8YXW21G+BkA5KTxCSJGnpd7hfAsodxp0Cu2Oa2uXdwqmOmXQ==");

        unsafe {
            let is_verified = unid_ciphers_hasher_verify(content.unwrap().as_ptr(), digest.unwrap().as_ptr(), secret.unwrap().as_ptr());

            assert!(is_verified);
        }
    }

    #[allow(clippy::eq_op)]
    #[test]
    fn it_works() {
        assert_eq!("hello", "hello");
    }

    #[test]
    fn always_failed() {
        assert_eq!("hello", "world");
    }
}
