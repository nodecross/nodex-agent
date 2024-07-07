use http_body_util::BodyExt;
use hyper::{body::Incoming, Method, Request, StatusCode};
use serde_json::json;
use std::fs::read;
use tokio::io::AsyncWriteExt as _;

use e2e::common::platform_client::{new_client, new_uri, response_to_string};

async fn create_verifiable_message_scenario() -> anyhow::Result<String> {
    let homedir = dirs::home_dir().unwrap();
    let client = new_client();

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
    let create_url = new_uri("/create-verifiable-message");
    let request = Request::builder()
        .method(Method::POST)
        .uri(create_url)
        .header("Content-Type", "application/json")
        .body(body)?;
    dbg!(&request);

    let response = client.request(request).await?;
    dbg!(&response);
    assert_eq!(response.status(), StatusCode::OK);

    let body: String = response_to_string(response).await?;
    // parse check
    let parsed = serde_json::from_str::<serde_json::Value>(&body)?;
    dbg!(&parsed);
    assert_eq!(
        parsed["credentialSubject"]["container"]["payload"],
        "Hello, world!"
    );

    Ok(body)
}

async fn verify_verifiable_message_scenario(input: String) -> anyhow::Result<()> {
    let homedir = dirs::home_dir().unwrap();
    let client = new_client();

    let body = json!({
        "message": input
    })
    .to_string();
    let verify_url = new_uri("/verify-verifiable-message");
    let request = Request::builder()
        .method(Method::POST)
        .uri(verify_url)
        .header("Content-Type", "application/json")
        .body(body)?;
    dbg!(&request);

    let response = client.request(request).await?;
    dbg!(&response);
    assert_eq!(response.status(), StatusCode::OK);

    let body: String = response_to_string(response).await?;
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
    let input = create_verifiable_message_scenario()
        .await
        .expect("failed to create_verifiable_message_scenario");
    verify_verifiable_message_scenario(input)
        .await
        .expect("failed to verify_verifiable_message_scenario");
}
