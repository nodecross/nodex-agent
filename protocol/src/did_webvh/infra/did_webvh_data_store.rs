use http::StatusCode;

#[derive(Clone, Debug)]
pub struct DidLogEntryResponse {
    pub(crate) status_code: StatusCode,
    pub(crate) body: String,
}

impl DidLogEntryResponse {
    pub fn new(status_code: StatusCode, body: String) -> Self {
        Self { status_code, body }
    }
}

#[trait_variant::make(Send)]
pub trait DidWebvhDataStore {
    type Error: std::error::Error;
    async fn post(
        &self,
        did_path: &str,
        did_log_entry: &str,
    ) -> Result<DidLogEntryResponse, Self::Error>;
    async fn get(&self, did_path: &str) -> Result<DidLogEntryResponse, Self::Error>;
    async fn put(
        &self,
        did_path: &str,
        did_log_entry: &str,
    ) -> Result<Vec<DidLogEntryResponse>, Self::Error>;
    async fn delete(&self, did_path: &str) -> Result<Vec<DidLogEntryResponse>, Self::Error>;
}
