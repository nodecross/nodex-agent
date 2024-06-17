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
            .route(
                "/events",
                web::post().to(controllers::public::send_event::handler),
            )
            // NOTE: Internal (Private) Routes
            .service(
                web::scope("/internal")
                    .route(
                        "/verifiable-credentials",
                        web::post().to(controllers::internal::did_generate_vc::handler),
                    )
                    .route(
                        "/verifiable-credentials/verify",
                        web::post().to(controllers::internal::did_verify_vc::handler),
                    )
                    .route(
                        "/verifiable-presentations",
                        web::post().to(controllers::internal::did_generate_vp::handler),
                    )
                    .route(
                        "/verifiable-presentations/verify",
                        web::post().to(controllers::internal::did_verify_vp::handler),
                    )
                    .route(
                        "/version/get",
                        web::get().to(controllers::internal::version::handler_get),
                    )
                    .route(
                        "/version/update",
                        web::post().to(controllers::internal::version::handler_update),
                    )
                    .route(
                        "/network",
                        web::post().to(controllers::internal::network::handler),
                    )
                    .service(
                        web::scope("/didcomm")
                            .route(
                                "/plaintext-messages",
                                web::post()
                                    .to(controllers::internal::didcomm_generate_plaintext::handler),
                            )
                            .route(
                                "/plaintext-messages/verify",
                                web::post()
                                    .to(controllers::internal::didcomm_verify_plaintext::handler),
                            )
                            .route(
                                "/signed-messages",
                                web::post()
                                    .to(controllers::internal::didcomm_generate_signed::handler),
                            )
                            .route(
                                "/signed-messages/verify",
                                web::post()
                                    .to(controllers::internal::didcomm_verify_signed::handler),
                            )
                            .route(
                                "/encrypted-messages",
                                web::post()
                                    .to(controllers::internal::didcomm_generate_encrypted::handler),
                            )
                            .route(
                                "/encrypted-messages/verify",
                                web::post()
                                    .to(controllers::internal::didcomm_verify_encrypted::handler),
                            ),
                    ),
            )
    })
    .bind_uds(sock_path)
    .unwrap()
    .workers(1)
    .run()
}
