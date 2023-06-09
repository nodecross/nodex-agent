use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct Credentials {
    pub credentials: CredentialsConfig,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CredentialsConfig {
    pub did: Option<String>,
    pub client_id: Option<String>,
    pub client_secret: Option<String>,    
}
