use crate::nodex::errors::NodeXError;
use reqwest::{
    header::{HeaderMap, HeaderValue},
    Proxy, Url,
};

pub struct HttpClientConfig {
    pub base_url: String,
    pub proxy: String,
}

#[derive(Clone, Debug)]
pub struct HttpClient {
    pub base_url: Url,
    pub instance: reqwest::Client,
}

impl HttpClient {
    pub fn new(_config: &HttpClientConfig) -> Result<Self, NodeXError> {
        let url = match Url::parse(&_config.base_url.to_string()) {
            Ok(v) => v,
            Err(e) => {
                log::error!("{:?}", e);
                return Err(NodeXError {});
            }
        };
        let client = Self::build_client(&_config.proxy);

        Ok(HttpClient {
            instance: client,
            base_url: url,
        })
    }

    fn default_headers(&self) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(
            reqwest::header::CONTENT_TYPE,
            HeaderValue::from_static("application/json"),
        );
        headers
    }

    fn build_client(proxy: &String) -> reqwest::Client {
        if proxy.is_empty() {
            return reqwest::Client::new();
        }
        reqwest::Client::builder()
            .proxy(Proxy::all(proxy).unwrap())
            .build()
            .unwrap()
    }

    pub async fn get(&self, _path: &str) -> Result<reqwest::Response, NodeXError> {
        let url = self.base_url.join(_path);

        match self
            .instance
            .get(&url.unwrap().to_string())
            .headers(self.default_headers())
            .send()
            .await
        {
            Ok(v) => Ok(v),
            Err(e) => {
                log::error!("{:?}", e);
                Err(NodeXError {})
            }
        }
    }

    pub async fn post(&self, _path: &str, body: &str) -> Result<reqwest::Response, NodeXError> {
        let url = self.base_url.join(_path);

        match self
            .instance
            .post(&url.unwrap().to_string())
            .headers(self.default_headers())
            .body(body.to_string())
            .send()
            .await
        {
            Ok(v) => Ok(v),
            Err(e) => {
                log::error!("{:?}", e);
                Err(NodeXError {})
            }
        }
    }

    #[allow(dead_code)]
    pub async fn put(&self, _path: &str) -> Result<reqwest::Response, NodeXError> {
        let url = self.base_url.join(_path);

        match self
            .instance
            .put(&url.unwrap().to_string())
            .headers(self.default_headers())
            .send()
            .await
        {
            Ok(v) => Ok(v),
            Err(e) => {
                log::error!("{:?}", e);
                Err(NodeXError {})
            }
        }
    }

    #[allow(dead_code)]
    pub async fn delete(&self, _path: &str) -> Result<reqwest::Response, NodeXError> {
        let url = self.base_url.join(_path);

        match self
            .instance
            .delete(&url.unwrap().to_string())
            .headers(self.default_headers())
            .send()
            .await
        {
            Ok(v) => Ok(v),
            Err(e) => {
                log::error!("{:?}", e);
                Err(NodeXError {})
            }
        }
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use serde::Deserialize;

    #[derive(Deserialize)]
    struct Res {
        origin: String,
    }

    #[actix_rt::test]
    #[ignore]
    async fn it_should_success_get() {
        let client_config: HttpClientConfig = HttpClientConfig {
            base_url: "https://httpbin.org".to_string(),
            proxy: "".to_string(),
        };

        let client = match HttpClient::new(&client_config) {
            Ok(v) => v,
            Err(_) => panic!(),
        };

        let res = match client.get("/get").await {
            Ok(v) => v,
            Err(_) => panic!(),
        };

        let json: Res = match res.json().await {
            Ok(v) => v,
            Err(_) => panic!(),
        };

        assert!(!json.origin.is_empty());
    }

    #[actix_rt::test]
    #[ignore]
    async fn it_should_success_post() {
        let client_config: HttpClientConfig = HttpClientConfig {
            base_url: "https://httpbin.org".to_string(),
            proxy: "".to_string(),
        };

        let client = match HttpClient::new(&client_config) {
            Ok(v) => v,
            Err(_) => panic!(),
        };

        let res = match client.post("/post", r#"{"key":"value"}"#).await {
            Ok(v) => v,
            Err(_) => panic!(),
        };

        let json: Res = match res.json().await {
            Ok(v) => v,
            Err(_) => panic!(),
        };

        assert!(!json.origin.is_empty());
    }

    #[actix_rt::test]
    #[ignore]
    async fn it_should_success_put() {
        let client_config: HttpClientConfig = HttpClientConfig {
            base_url: "https://httpbin.org".to_string(),
            proxy: "".to_string(),
        };

        let client = match HttpClient::new(&client_config) {
            Ok(v) => v,
            Err(_) => panic!(),
        };

        let res = match client.put("/put").await {
            Ok(v) => v,
            Err(_) => panic!(),
        };

        let json: Res = match res.json().await {
            Ok(v) => v,
            Err(_) => panic!(),
        };

        assert!(!json.origin.is_empty());
    }

    #[actix_rt::test]
    #[ignore]
    async fn it_should_success_delete() {
        let client_config: HttpClientConfig = HttpClientConfig {
            base_url: "https://httpbin.org".to_string(),
            proxy: "".to_string(),
        };

        let client = match HttpClient::new(&client_config) {
            Ok(v) => v,
            Err(_) => panic!(),
        };

        let res = match client.delete("/delete").await {
            Ok(v) => v,
            Err(_) => panic!(),
        };

        let json: Res = match res.json().await {
            Ok(v) => v,
            Err(_) => panic!(),
        };

        assert!(!json.origin.is_empty());
    }
}
