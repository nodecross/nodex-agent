pub mod did_vc;
pub mod didcomm_encrypted;
pub mod types;
use crate::server_config;

fn attachment_link() -> String {
    let server_config = server_config();
    server_config.did_attachment_link()
}
