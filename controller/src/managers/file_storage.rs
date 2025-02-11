use super::runtime::{RuntimeError, RuntimeInfo, RuntimeInfoStorage, State};
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, Write};
use std::path::PathBuf;

#[derive(Debug)]
pub struct FileHandler {
    file: File,
}

impl RuntimeInfoStorage for FileHandler {
    fn read(&mut self) -> Result<RuntimeInfo, RuntimeError> {
        let mut content = String::new();
        self.file
            .read_to_string(&mut content)
            .map_err(RuntimeError::FileRead)?;
        self.file
            .seek(std::io::SeekFrom::Start(0))
            .map_err(RuntimeError::FileRead)?;
        if content.trim().is_empty() {
            // We assume that the file is empty means that it is the first execution.
            let process_infos = [None, None, None, None];
            return Ok(RuntimeInfo {
                state: State::Idle,
                process_infos,
                exec_path: std::env::current_exe().map_err(RuntimeError::FailedCurrentExe)?,
            });
        }
        serde_json::from_str(&content).map_err(RuntimeError::JsonDeserialize)
    }

    fn apply_with_lock<F>(&mut self, operation: F) -> Result<(), RuntimeError>
    where
        F: FnOnce(&mut RuntimeInfo) -> Result<(), RuntimeError>,
    {
        fs2::FileExt::lock_exclusive(&self.file)
            .map_err(self.handle_err(RuntimeError::FileLock))?;

        let mut runtime_info = self.read().map_err(self.handle_err_id())?;

        operation(&mut runtime_info).map_err(self.handle_err_id())?;

        self.write_locked(&runtime_info)
            .map_err(self.handle_err_id())?;
        fs2::FileExt::unlock(&self.file).map_err(RuntimeError::FileUnlock)?;

        Ok(())
    }
}

impl FileHandler {
    pub fn new(path: PathBuf) -> Result<Self, RuntimeError> {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&path)
            .map_err(RuntimeError::FileOpen)?;
        Ok(FileHandler { file })
    }

    fn handle_err_id(&mut self) -> impl Fn(RuntimeError) -> RuntimeError + '_ {
        self.handle_err(|x| x)
    }

    fn handle_err<'a, E>(
        &'a mut self,
        error: impl Fn(E) -> RuntimeError + 'a,
    ) -> impl Fn(E) -> RuntimeError + 'a {
        move |e| {
            let res = fs2::FileExt::unlock(&self.file).map_err(RuntimeError::FileUnlock);
            if let Err(res) = res {
                return res;
            }
            error(e)
        }
    }

    fn write_locked(&mut self, runtime_info: &RuntimeInfo) -> Result<(), RuntimeError> {
        let json_data =
            serde_json::to_string_pretty(runtime_info).map_err(RuntimeError::JsonSerialize)?;

        self.file.set_len(0).map_err(RuntimeError::FileWrite)?;

        self.file
            .seek(std::io::SeekFrom::Start(0))
            .map_err(RuntimeError::FileWrite)?;

        self.file
            .write_all(json_data.as_bytes())
            .map_err(RuntimeError::FileWrite)?;

        self.file.flush().map_err(RuntimeError::FileWrite)?;

        self.file
            .seek(std::io::SeekFrom::Start(0))
            .map_err(RuntimeError::FileWrite)?;

        log::info!("File written successfully");
        Ok(())
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use crate::managers::runtime::{
        FeatType, ProcessInfo, RuntimeInfo, RuntimeManagerImpl, RuntimeManagerWithoutAsync,
    };
    use crate::managers::unix_process_manager::UnixProcessManager;
    use std::fs::File;
    use tempfile::tempdir;

    #[test]
    fn test_read_write_runtime_info() {
        let initial_runtime_info = RuntimeInfo {
            state: State::Update,
            process_infos: [None, None, None, None],
            exec_path: std::env::current_exe().unwrap(),
        };
        let tempdir = tempdir().expect("Failed to create temporary directory");
        let temp_file_path = tempdir.path().join("runtime_info.json");
        let mut file_handler = FileHandler::new(temp_file_path.clone()).unwrap();

        file_handler
            .apply_with_lock(|runtime_info| {
                *runtime_info = initial_runtime_info.clone();
                Ok(())
            })
            .unwrap();

        let read_runtime_info = file_handler.read().unwrap();
        assert_eq!(read_runtime_info, initial_runtime_info);
    }

    #[test]
    fn test_update_state() {
        let temp_dir = tempdir().expect("Failed to create temporary directory");
        let temp_file_path = temp_dir.path().join("runtime_info.json");
        File::create(&temp_file_path).expect("Failed to create temporary runtime_info.json");
        let file_handler = FileHandler::new(temp_file_path.clone()).unwrap();
        let mut runtime_manager =
            RuntimeManagerImpl::new_by_agent(file_handler, UnixProcessManager);

        runtime_manager
            .update_state_without_send(State::Update)
            .unwrap();

        let state = runtime_manager.get_runtime_info().unwrap().state;

        assert_eq!(state, State::Update);
    }

    #[test]
    fn test_cleanup_process_info() {
        let temp_dir = tempdir().expect("Failed to create temporary directory");
        let temp_file_path = temp_dir.path().join("runtime_info.json");
        File::create(&temp_file_path).expect("Failed to create temporary runtime_info.json");

        let process_info = ProcessInfo::new((1 << 22) + 1, FeatType::Agent);
        let runtime_info = RuntimeInfo {
            state: State::Idle,
            process_infos: [Some(process_info.clone()), None, None, None],
            exec_path: std::env::current_exe().unwrap(),
        };
        let mut file_handler = FileHandler::new(temp_file_path.clone()).unwrap();
        file_handler.write_locked(&runtime_info).unwrap();

        let mut runtime_manager = RuntimeManagerImpl::new_by_controller(
            file_handler,
            UnixProcessManager,
            "/tmp/nodex.sock",
        )
        .unwrap()
        .0;

        let process_infos: Vec<_> = runtime_manager
            .get_runtime_info()
            .unwrap()
            .process_infos
            .into_iter()
            .flatten()
            .collect();
        assert!(!process_infos.contains(&process_info));
    }

    // TODO: Fix fork bomb
    // #[tokio::test]
    // async fn test_launch_and_terminate_agent() {
    //     let temp_dir = tempfile::tempdir().unwrap();
    //     let temp_file_path = temp_dir.path().join("runtime_info.json");
    //     File::create(&temp_file_path).expect("Failed to create temporary runtime_info.json");
    //     let uds_path = temp_dir.path().join("test_socket");
    //     let file_handler = FileHandler::new(temp_file_path.clone()).unwrap();
    //     let mut manager = RuntimeManagerImpl::new_by_controller(
    //         file_handler,
    //         UnixProcessManager,
    //         uds_path,
    //     )
    //     .unwrap()
    //     .0;

    //     let process_info = manager.launch_agent(false);
    //     assert!(process_info.is_ok(), "Agent launch should succeed");

    //     let process_info = process_info.unwrap();
    //     assert!(
    //         manager.kill_process(&process_info).is_ok(),
    //         "Agent termination should succeed"
    //     );
    // }
}
