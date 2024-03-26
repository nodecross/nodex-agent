use anyhow::Context as _;
use async_trait::async_trait;
use nodex_didcomm::did::sidetree::client::{
    HttpError, SidetreeHttpClient, SidetreeHttpClientResponse,
};

#[derive(Clone)]
pub struct SideTreeClient {
    base_url: reqwest::Url,
    client: reqwest::Client,
}

impl SideTreeClient {
    pub fn new(base_url: &str) -> anyhow::Result<Self> {
        let base_url =
            reqwest::Url::parse(base_url).context("NODEX_DID_HTTP_ENDPOINT must be a valid URL")?;
        Ok(Self {
            base_url,
            client: reqwest::Client::new(),
        })
    }
}

#[async_trait]
impl SidetreeHttpClient for SideTreeClient {
    async fn post_create_identifier(
        &self,
        body: &str,
    ) -> Result<SidetreeHttpClientResponse, HttpError> {
        let url = self.base_url.join("/api/v1/operations")?;

        let response = self
            .client
            .post(url)
            .header("Content-Type", "application/json")
            .body(body.to_string())
            .send()
            .await?;

        let status = response.status().as_u16();
        let body = response.text().await?;

        let response = SidetreeHttpClientResponse::new(status, body)?;

        Ok(response)
    }
    async fn get_find_identifier(
        &self,
        did: &str,
    ) -> Result<SidetreeHttpClientResponse, HttpError> {
        let url = self
            .base_url
            .join(&format!("/api/v1/identifiers/{}", did))?;

        let response = self.client.get(url).send().await?;

        let response =
            SidetreeHttpClientResponse::new(response.status().as_u16(), response.text().await?)?;

        Ok(response)
    }
}
