pub mod didcomm_message_usecase;
pub mod metric_collector_usecase;
pub mod metric_sender_usecase;
pub mod verifiable_message_usecase;

fn get_my_did() -> String {
    let config = crate::app_config();
    let config = config.lock();
    config.get_did().unwrap().to_string()
}
