use crate::{controllers, handlers::TransferClient};
use actix_web::{dev::Server, middleware, web, App, HttpServer};
use std::path::PathBuf;
use tokio::sync::Mutex as TokioMutex;

pub struct Context<C: TransferClient> {
    pub sender: TokioMutex<C>,
}

#[cfg(unix)]
pub fn new_uds_server<C: TransferClient + 'static>(sock_path: &PathBuf, sender: C) -> Server {
    let context = web::Data::new(Context {
        sender: TokioMutex::new(sender),
    });

    HttpServer::new(move || {
        App::new()
            .wrap(middleware::DefaultHeaders::new().add(("x-version", "0.1.0")))
            .wrap(middleware::Compress::default())
            .wrap(middleware::Logger::default())
            .configure(config_app(&context))
    })
    .bind_uds(sock_path)
    .unwrap()
    .workers(1)
    .run()
}

#[cfg(windows)]
pub fn new_web_server<C: TransferClient + 'static>(port: u16, sender: C) -> Server {
    let context = web::Data::new(Context {
        sender: TokioMutex::new(sender),
    });

    HttpServer::new(move || {
        App::new()
            .wrap(middleware::DefaultHeaders::new().add(("x-version", "0.1.0")))
            .wrap(middleware::Compress::default())
            .wrap(middleware::Logger::default())
            .configure(config_app(&context))
    })
    .bind(format!("127.0.0.1:{}", port))
    .unwrap()
    .workers(1)
    .run()
}

fn config_app<C: TransferClient + 'static>(
    context: &web::Data<Context<C>>,
) -> impl Fn(&mut web::ServiceConfig) + '_ {
    move |cfg: &mut web::ServiceConfig| {
        cfg.app_data(context.clone())
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
            .route(
                "/custom_metrics",
                web::post().to(controllers::public::send_custom_metric::handler),
            )
            .route(
                "/attributes",
                web::post().to(controllers::public::send_attribute::handler),
            )
            // NOTE: Internal (Private) Routes
            .service(
                web::scope("/internal")
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
                    ),
            );
    }
}
