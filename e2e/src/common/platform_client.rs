use http_body_util::BodyExt;
use hyper::{
    body::{Body, Incoming},
    Response, Uri as HyperUri,
};
use hyper_util::client::legacy::Client as LegacyClient;
use std::boxed::Box;
use std::error::Error as StdError;
use tokio::io::AsyncWriteExt as _;

#[cfg(unix)]
mod platform_specific {
    pub use hyperlocal::{UnixClientExt, UnixConnector, Uri as HyperLocalUri};
    pub use std::path::PathBuf;
}

#[cfg(windows)]
mod platform_specific {
    pub use hyper_util::client::legacy::connect::HttpConnector;
    pub use hyper_util::rt::TokioExecutor;
}

use platform_specific::*;

pub enum GenericUri {
    #[cfg(unix)]
    Unix(HyperLocalUri),
    #[cfg(windows)]
    Http(HyperUri),
}

impl GenericUri {
    #[cfg(unix)]
    pub fn new_unix(socket_path: PathBuf, path: &str) -> Self {
        Self::Unix(HyperLocalUri::new(socket_path, path))
    }

    #[cfg(windows)]
    pub fn new_http(base_url: &str, path: &str) -> Self {
        let full_url = format!("{}{}", base_url, path);
        Self::Http(full_url.parse().expect("Failed to parse URL"))
    }
}

pub fn new_uri(url: &str) -> hyper::Uri {
    #[cfg(unix)]
    {
        let homedir = dirs::home_dir().expect("Home directory not found");
        let socket_path = homedir.join(".nodex/run/nodex.sock");
        let generic_uri = GenericUri::new_unix(socket_path, url);
        match generic_uri {
            GenericUri::Unix(uri) => uri.into(),
            _ => panic!("Invalid URI type"),
        }
    }
    #[cfg(windows)]
    {
        let generic_uri = GenericUri::new_http("http://localhost:3000", url);
        match generic_uri {
            GenericUri::Http(uri) => uri.into(),
            _ => panic!("Invalid URI type"),
        }
    }
}

#[cfg(unix)]
pub fn new_client<B>() -> LegacyClient<UnixConnector, B>
where
    B: Body + Send + 'static + Unpin,
    B::Data: Send,
    B::Error: Into<Box<dyn StdError + Send + Sync>>,
{
    LegacyClient::<UnixConnector, B>::unix()
}

#[cfg(windows)]
pub fn new_client<B>() -> LegacyClient<HttpConnector, B>
where
    B: Body + Send + 'static + Unpin,
    B::Data: Send,
    B::Error: Into<Box<dyn StdError + Send + Sync>>,
{
    let http_connector = HttpConnector::new();
    let executor = TokioExecutor::new();
    LegacyClient::builder(executor).build(http_connector)
}

pub async fn response_to_string(mut response: Response<Incoming>) -> anyhow::Result<String> {
    let mut body: Vec<u8> = Vec::with_capacity(2048);

    while let Some(frame_result) = response.frame().await {
        let frame = frame_result?;

        if let Some(segment) = frame.data_ref() {
            body.write_all(segment.iter().as_slice()).await?;
        }
    }

    Ok(String::from_utf8(body)?)
}
