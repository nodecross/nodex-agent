use crate::config::app_config;
use crate::controllers;
use axum::{
    extract::DefaultBodyLimit,
    routing::{get, post},
    Router,
};

#[cfg(unix)]
pub mod unix {
    use axum::Router;
    use controller::unix_utils::{
        convention_of_meta_uds_path, recv_fd, remove_file_if_exists, send_fd,
    };
    use std::os::unix::fs::PermissionsExt;
    use std::os::unix::io::{AsRawFd, FromRawFd, RawFd};
    use std::path::Path;
    use tokio::net::{UnixListener, UnixStream};
    use tokio::signal::unix::{signal, SignalKind};
    use tokio::task::JoinSet;
    use tokio_util::sync::CancellationToken;

    pub fn recieve_listener(uds_path: impl AsRef<Path>) -> std::io::Result<UnixListener> {
        let meta_uds_path = convention_of_meta_uds_path(&uds_path)?;
        remove_file_if_exists(&meta_uds_path);
        let sock = std::os::unix::net::UnixListener::bind(&meta_uds_path)?;
        let permissions = std::fs::Permissions::from_mode(0o766);
        std::fs::set_permissions(&meta_uds_path, permissions)?;
        let (stream, _) = sock.accept()?;
        let fd = recv_fd(stream.as_raw_fd())?;
        remove_file_if_exists(&meta_uds_path);
        let uds = match fd {
            Some(fd) => {
                let listener =
                    unsafe { std::os::unix::net::UnixListener::from_raw_fd(fd as RawFd) };
                UnixListener::from_std(listener)?
            }
            None => {
                remove_file_if_exists(&uds_path);
                UnixListener::bind(&uds_path)?
            }
        };
        Ok(uds)
    }

    pub async fn make_uds_server(router: Router, uds: UnixListener) -> std::io::Result<()> {
        // https://github.com/tokio-rs/axum/blob/main/examples/unix-domain-socket/src/main.rs
        let app = router.into_make_service();
        axum::serve(uds, app).await
    }

    pub fn wrap_with_signal_handler(
        server: impl std::future::Future<Output = std::io::Result<()>> + Send + 'static,
        token: CancellationToken,
        fd: RawFd,
        uds_path: impl AsRef<Path>,
    ) -> JoinSet<std::io::Result<()>> {
        let mut set = JoinSet::new();
        let cloned_token = token.clone();
        let tasks = async move {
            tokio::select! {
                _ = cloned_token.cancelled() => Ok(()),
                res = server => res,
            }
        };
        set.spawn(tasks);
        let uds_path = uds_path.as_ref().to_owned();
        set.spawn(async move {
            let ctrl_c = tokio::signal::ctrl_c();
            let mut sigterm = signal(SignalKind::terminate())?;
            let mut sigusr1 = signal(SignalKind::user_defined1())?;
            tokio::select! {
                _ = ctrl_c => {
                    log::info!("Received Ctrl+C");
                    token.cancel();
                    Ok(())
                },
                _ = sigterm.recv() => {
                    log::info!("Received SIGTERM");
                    token.cancel();
                    Ok(())
                },
                _ = sigusr1.recv() => {
                    log::info!("Received SIGUSR1");
                    let send_sock_path = convention_of_meta_uds_path(&uds_path)?;
                    let () = controller::unix_utils::wait_until_file_created(&send_sock_path)
                        .map_err(|e| std::io::Error::new(std::io::ErrorKind::NotFound, format!("{}", e)))?;
                    let stream = loop {
                        match UnixStream::connect(&send_sock_path).await {
                            Ok(stream) => break stream,
                            Err(err) if err.kind() == std::io::ErrorKind::ConnectionRefused => {
                                // Wait for bind
                                tokio::time::sleep(std::time::Duration::from_millis(5)).await;
                                continue;
                            }
                            Err(err) => return Err(err),
                        }
                    };
                    send_fd(stream.as_raw_fd(), Some(fd))?;
                    token.cancel();
                    Ok(())
                }
            }
        });
        set
    }
}

#[cfg(windows)]
pub mod windows {
    use crate::nodex::utils::UnwrapLog;
    use anyhow::anyhow;
    use axum::Router;
    use std::future::IntoFuture;
    use sysinfo::{get_current_pid, System};
    use windows::Win32::{
        Foundation::{CloseHandle, GetLastError},
        System::Threading::{OpenProcess, TerminateProcess, PROCESS_TERMINATE},
    };

    pub async fn new_web_server(
        port: u16,
        router: Router,
    ) -> Result<impl std::future::Future<Output = Result<(), std::io::Error>>, std::io::Error> {
        // run our app with hyper, listening globally on port 3000
        let listener = tokio::net::TcpListener::bind(format!("127.0.0.1:{}", port)).await?;
        Ok(axum::serve(listener, router).into_future())
    }

    pub fn validate_port(port_str: &str) -> Result<u16, String> {
        match port_str.parse::<u16>() {
            Ok(port) if (1024..=65535).contains(&port) => Ok(port),
            _ => Err("Port number must be an integer between 1024 and 65535.".to_string()),
        }
    }

    pub fn kill_other_self_process() {
        let current_pid = get_current_pid().unwrap_log();
        let mut system = System::new_all();
        system.refresh_all();

        let process_name = { "nodex-agent.exe" };
        for process in system.processes_by_exact_name(process_name) {
            if current_pid == process.pid() {
                continue;
            }
            if process.parent() == Some(current_pid) {
                continue;
            }

            let pid = process.pid().as_u32();
            if let Err(e) = kill_process(pid) {
                log::error!("Failed to kill process with PID: {}. Error: {:?}", pid, e);
            }
        }
    }

    fn kill_process(pid: u32) -> Result<(), anyhow::Error> {
        unsafe {
            let handle = OpenProcess(PROCESS_TERMINATE, false, pid)?;
            if handle.is_invalid() {
                return Err(anyhow!(
                    "Failed to open process with PID: {}. Invalid handle.",
                    pid
                ));
            }

            match TerminateProcess(handle, 1) {
                Ok(_) => {
                    log::info!("nodex Process with PID: {} killed successfully.", pid);
                }
                Err(e) => {
                    CloseHandle(handle);
                    return Err(anyhow!(
                        "Failed to terminate process with PID: {}. Error: {:?}",
                        pid,
                        GetLastError()
                    ));
                }
            };
            CloseHandle(handle);
        }

        Ok(())
    }
}

pub fn make_router() -> Router {
    let body_limit = app_config().lock().get_didcomm_body_size();
    Router::new()
        .route(
            "/identifiers",
            post(controllers::public::nodex_create_identifier::handler),
        )
        .route(
            "/identifiers/{did}",
            get(controllers::public::nodex_find_identifier::handler),
        )
        .route(
            "/create-verifiable-message",
            post(controllers::public::nodex_create_verifiable_message::handler),
        )
        .route(
            "/verify-verifiable-message",
            post(controllers::public::nodex_verify_verifiable_message::handler),
        )
        .route(
            "/create-didcomm-message",
            post(controllers::public::nodex_create_didcomm_message::handler),
        )
        .layer(DefaultBodyLimit::max(body_limit))
        .route(
            "/verify-didcomm-message",
            post(controllers::public::nodex_verify_didcomm_message::handler),
        )
        .layer(DefaultBodyLimit::max(body_limit))
        .route("/events", post(controllers::public::send_event::handler))
        .route(
            "/custom-metrics",
            post(controllers::public::send_custom_metric::handler),
        )
        .route(
            "/attributes",
            post(controllers::public::send_attribute::handler),
        )
        // NOTE: Internal (Private) Routes
        .route(
            "/internal/version/get",
            get(controllers::internal::version::handler_get),
        )
        .route(
            "/internal/version/update",
            post(controllers::internal::version::handler_update),
        )
        .route(
            "/internal/network",
            post(controllers::internal::network::handler),
        )
}
