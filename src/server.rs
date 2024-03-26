use crate::{controllers, handlers::TransferClient};
use actix_web::{dev::Server, middleware, web, App, HttpServer};
use std::path::PathBuf;
use tokio::sync::Mutex as TokioMutex;

pub struct Context {
    pub sender: TokioMutex<Box<dyn TransferClient>>,
}

pub fn new_server(sock_path: &PathBuf, sender: Box<dyn TransferClient>) -> Server {
    let context = web::Data::new(Context {
        sender: TokioMutex::new(sender),
    });

    HttpServer::new(move || {
        App::new()
            .wrap(middleware::DefaultHeaders::new().add(("x-version", "0.1.0")))
            .wrap(middleware::Compress::default())
            .wrap(middleware::Logger::default())
            .app_data(context.clone())
            // NOTE: Public Routes
            .route(
                "/identifiers",
                web::post().to(controllers::public::nodex_create_identifier::handler),
            )
            .route(
                "/identifiers/{did}",
                web::get().to(controllers::public::nodex_find_identifier::handler),
            )
            .route(
                "/create-verifiable-message",
                web::post().to(controllers::public::nodex_create_verifiable_message::handler),
            )
            .route(
                "/verify-verifiable-message",
                web::post().to(controllers::public::nodex_verify_verifiable_message::handler),
            )
            .route(
                "/create-didcomm-message",
                web::post().to(controllers::public::nodex_create_didcomm_message::handler),
            )
            .route(
                "/verify-didcomm-message",
                web::post().to(controllers::public::nodex_verify_didcomm_message::handler),
            )
            // NOTE: Internal (Private) Routes
            .service(
                web::scope("/internal")
                    .route(
                        "/version/get",
                        web::post().to(controllers::internal::version::handler_get),
                    )
                    .route(
                        "/version/update",
                        web::post().to(controllers::internal::version::handler_update),
                    )
                    .route(
                        "/network",
                        web::post().to(controllers::internal::network::handler),
                    ),
            )
    })
    .bind_uds(sock_path)
    .unwrap()
    .workers(1)
    .run()
}
