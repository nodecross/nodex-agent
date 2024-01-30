use crate::nodex::schema::general::GeneralVcDataModel;
use crate::services::nodex::NodeX;
use crate::{
    network::Network,
    nodex::errors::NodeXError,
    server,
    services::{hub::Hub, internal::didcomm_encrypted::DIDCommEncryptedService},
};
use actix::prelude::*;
use actix::{Actor, ActorContext, StreamHandler};
use actix_web::{web, HttpRequest, HttpResponse};
use actix_web_actors::ws;
use serde::{Deserialize, Serialize};
use std::{
    collections::HashSet,
    sync::{atomic::AtomicBool, Arc, RwLock},
    time::Duration,
};

#[derive(Deserialize)]
enum OperationType {
    UpdateAgent,
    UpdateNetworkJson,
}

#[derive(Debug, Clone)]
pub struct ConnectionRepository {
    connections: Arc<RwLock<HashSet<Addr<MessageReceiveActor>>>>,
}

impl ConnectionRepository {
    pub fn new() -> Self {
        Self {
            connections: Arc::new(RwLock::new(HashSet::new())),
        }
    }

    pub fn connection_count(&self) -> usize {
        self.connections.read().unwrap().len()
    }

    pub fn insert(&mut self, addr: Addr<MessageReceiveActor>) -> bool {
        self.connections.write().unwrap().insert(addr)
    }

    pub fn remove(&mut self, addr: &Addr<MessageReceiveActor>) -> bool {
        self.connections.write().unwrap().remove(addr)
    }

    fn send_all(&self, msg: ResponseJson) {
        for addr in self.connections.read().unwrap().iter() {
            addr.do_send(msg.clone());
        }
    }
}

pub struct MessageReceiveActor {
    connections: ConnectionRepository,
}

impl MessageReceiveActor {
    pub fn new(connections: ConnectionRepository) -> Self {
        Self { connections }
    }
}

#[derive(Deserialize, Serialize, Debug, Clone, Message)]
#[rtype(result = "Result<(), ()>")]
struct ResponseJson {
    pub message_id: String,
    pub message: GeneralVcDataModel,
}

#[derive(Deserialize, Serialize, Debug, Clone)]
struct AckMessage {
    pub message_id: String,
}

struct MessageReceiveUsecase {
    hub: Hub,
    agent: NodeX,
    project_did: String,
}

impl MessageReceiveUsecase {
    pub fn new() -> Self {
        let network = Network::new();
        let project_did = if let Some(v) = network.root.project_did {
            v
        } else {
            panic!("Failed to read project_did")
        };

        Self {
            hub: Hub::new(),
            agent: NodeX::new(),
            project_did,
        }
    }

    pub async fn receive_message(&self) -> Result<Vec<ResponseJson>, NodeXError> {
        let mut responses = Vec::new();

        for m in self.hub.get_message(&self.project_did).await? {
            let json_message = serde_json::from_str(&m.raw_message).map_err(|e| {
                log::error!("Invalid Json: {:?}", e);
                NodeXError {}
            })?;
            log::info!("Receive message. message_id = {:?}", m.id);
            match DIDCommEncryptedService::verify(&json_message).await {
                Ok(verified) => {
                    log::info!(
                        "Verify success. message_id = {}, from = {}",
                        m.id,
                        verified.message.issuer.id
                    );
                    let response = ResponseJson {
                        message_id: m.id,
                        message: verified.message.clone(),
                    };
                    if verified.message.issuer.id == self.project_did {
                        let container = verified.message.credential_subject.container;
                        let operation_type = container["operation"].clone();
                        match serde_json::from_value::<OperationType>(operation_type) {
                            Ok(OperationType::UpdateAgent) => {
                                let binary_url = match container["binary_url"].as_str() {
                                    Some(url) => url,
                                    None => return Err(NodeXError {}),
                                };
                                self.agent.update_version(binary_url, "/tmp").await?;
                                self.hub
                                    .ack_message(&self.project_did, response.message_id, true)
                                    .await?;
                            }
                            Ok(OperationType::UpdateNetworkJson) => {
                                self.hub.network().await?;
                                self.hub
                                    .ack_message(&self.project_did, response.message_id, true)
                                    .await?;
                            }
                            Err(e) => {
                                log::error!("Error: {:?}", e);
                            }
                        }
                        continue;
                    }
                    responses.push(response);
                }
                Err(_) => {
                    log::error!("Verify failed : message_id = {}", m.id);
                    self.hub.ack_message(&self.project_did, m.id, false).await?;
                    continue;
                }
            }
        }

        Ok(responses)
    }

    async fn ack_message(&self, message_id: String) {
        match self
            .hub
            .ack_message(&self.project_did, message_id.clone(), true)
            .await
        {
            Ok(_) => log::info!("Ack message success : message_id = {}", message_id),
            Err(e) => log::error!("Failed to ack message : {:?}", e),
        }
    }
}

impl Actor for MessageReceiveActor {
    type Context = ws::WebsocketContext<Self>;

    fn started(&mut self, ctx: &mut Self::Context) {
        log::info!("Actor started");
        self.connections.insert(ctx.address());
    }

    fn stopping(&mut self, ctx: &mut Self::Context) -> Running {
        log::info!("Actor is stopping");
        self.connections.remove(&ctx.address());
        Running::Stop
    }
}

impl Handler<ResponseJson> for MessageReceiveActor {
    type Result = Result<(), ()>;

    fn handle(&mut self, msg: ResponseJson, ctx: &mut Self::Context) -> Self::Result {
        let msg = serde_json::to_string(&msg).map_err(|e| log::error!("Error: {:?}", e))?;
        ctx.text(msg);

        Ok(())
    }
}

impl StreamHandler<Result<ws::Message, ws::ProtocolError>> for MessageReceiveActor {
    fn handle(&mut self, item: Result<ws::Message, ws::ProtocolError>, ctx: &mut Self::Context) {
        let msg = match item {
            Ok(msg) => msg,
            Err(e) => {
                log::error!("Error: {:?}", e);
                ctx.stop();
                return;
            }
        };

        match msg {
            ws::Message::Ping(msg) => ctx.pong(&msg),
            ws::Message::Text(text) => {
                let text = text.to_string();
                match serde_json::from_str::<AckMessage>(&text) {
                    Ok(v) => {
                        ctx.wait(
                            async {
                                MessageReceiveUsecase::new().ack_message(v.message_id).await;
                            }
                            .into_actor(self),
                        );
                    }
                    Err(e) => {
                        log::error!("Invalid Json: {:?}", e);
                    }
                };
            }
            ws::Message::Close(reason) => {
                ctx.close(reason);
                ctx.stop();
            }
            ws::Message::Binary(_) | ws::Message::Continuation(_) => {
                log::error!("Not supported");
                ctx.stop();
            }
            ws::Message::Pong(_) | ws::Message::Nop => (),
        }
    }
}

pub async fn handler(
    req: HttpRequest,
    context: web::Data<server::Context>,
    stream: web::Payload,
) -> actix_web::Result<HttpResponse> {
    let actor = MessageReceiveActor::new(context.connections.clone());
    let resp = ws::start(actor, &req, stream);
    log::info!("{:?}", resp);
    resp
}

pub async fn polling_task(
    shutdown_marker: Arc<AtomicBool>,
    connection_repository: ConnectionRepository,
) {
    log::info!("Polling task is started");

    let usecase = MessageReceiveUsecase::new();

    let mut interval = tokio::time::interval(Duration::from_secs(5));
    while !shutdown_marker.load(std::sync::atomic::Ordering::SeqCst) {
        interval.tick().await;
        match usecase.receive_message().await {
            Ok(messages) => messages
                .into_iter()
                .for_each(|msg| connection_repository.send_all(msg)),
            Err(e) => log::error!("Error: {:?}", e),
        }
    }

    log::info!("Polling task is stopped")
}
