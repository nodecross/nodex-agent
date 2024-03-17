use http_body_util::BodyExt;
use hyper::{body::Incoming, Method, Request, StatusCode};
use hyper_util::client::legacy::Client;
use hyperlocal::{UnixClientExt, UnixConnector, Uri as HyperLocalUri};
use serde_json::json;
use std::fs::read;
use tokio::io::AsyncWriteExt as _;

async fn response_to_string(mut response: hyper::Response<Incoming>) -> anyhow::Result<String> {
    let mut body: Vec<u8> = Vec::with_capacity(2048);

    while let Some(frame_result) = response.frame().await {
        let frame = frame_result?;

        if let Some(segment) = frame.data_ref() {
            body.write_all(segment.iter().as_slice()).await?;
        }
    }

    Ok(String::from_utf8(body)?)
}

async fn create_didcomm_message_scenario() -> anyhow::Result<String> {
    let homedir = dirs::home_dir().unwrap();
    let socket_path = homedir.join(".nodex/run/nodex.sock");
    let client: Client<UnixConnector, _> = Client::unix();

    let create_url = HyperLocalUri::new(&socket_path, "/create-didcomm-message");

    let my_did = {
        let config = read(homedir.join(".config/nodex/config.json"))?;
        let config = serde_json::from_slice::<serde_json::Value>(&config)?;
        config["did"].as_str().unwrap().to_string()
    };

    let body = json!({
        "destination_did": my_did,
        "operation_tag": "test",
        "message": "Hello, world!"
    })
    .to_string();

    let request = Request::builder()
        .method(Method::POST)
        .uri(create_url)
        .header("Content-Type", "application/json")
        .body(body)?;
    dbg!(&request);

    let response = client.request(request).await?;
    dbg!(&response);

    assert_eq!(response.status(), StatusCode::OK);

    let body = response_to_string(response).await?;
    // parse check
    let _ = serde_json::from_str::<serde_json::Value>(&body)?;

    Ok(body)
}

async fn verify_didcomm_message_scenario(input: String) -> anyhow::Result<()> {
    let homedir = dirs::home_dir().unwrap();
    let socket_path = homedir.join(".nodex/run/nodex.sock");
    let client: Client<UnixConnector, _> = Client::unix();

    let verify_url = HyperLocalUri::new(&socket_path, "/verify-didcomm-message");

    let body = json!({
        "message": input
    })
    .to_string();

    let request = Request::builder()
        .method(Method::POST)
        .uri(verify_url)
        .header("Content-Type", "application/json")
        .body(body)?;

    dbg!(&request);

    let response = client.request(request).await?;
    dbg!(&response);

    assert_eq!(response.status(), StatusCode::OK);

    let body = response_to_string(response).await?;
    let body_json = serde_json::from_str::<serde_json::Value>(&body)?;

    assert_eq!(
        body_json["credentialSubject"]["container"]["payload"]
            .as_str()
            .unwrap(),
        "Hello, world!"
    );

    Ok(())
}

#[tokio::test]
async fn test() {
    let input = create_didcomm_message_scenario()
        .await
        .expect("failed to create_didcomm_message_scenario");
    verify_didcomm_message_scenario(input)
        .await
        .expect("failed to verify_didcomm_message_scenario");
}
