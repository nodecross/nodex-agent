use super::runtime::{NodexSignal, ProcessManager};
use nix::{
    sys::signal::{self, Signal},
    unistd::{execvp, fork, setsid, ForkResult, Pid},
};
use std::ffi::CString;
use std::path::Path;

#[derive(Clone)]
pub struct UnixProcessManager;

#[inline]
fn nule_to_ioe(e: std::ffi::NulError) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidInput, e)
}

impl ProcessManager for UnixProcessManager {
    fn is_running(&self, process_id: u32) -> bool {
        let pid = Pid::from_raw(process_id as i32);
        match signal::kill(pid, None) {
            Ok(()) => true,
            Err(_) => false,
        }
    }
    fn spawn_process(&self, cmd: impl AsRef<Path>, args: &[&str]) -> Result<u32, std::io::Error> {
        let cmd = CString::new(cmd.as_ref().to_string_lossy().into_owned()).map_err(nule_to_ioe)?;
        let args: Result<Vec<_>, _> = args
            .iter()
            .map(|arg| CString::new(*arg).map_err(nule_to_ioe))
            .collect();
        let mut args = args?;
        args.splice(0..0, vec![cmd.clone()]);

        match unsafe { fork() } {
            Ok(ForkResult::Parent { child }) => Ok(child.as_raw() as _),
            Ok(ForkResult::Child) => {
                setsid().map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
                execvp(&cmd, &args)
                    .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
                unreachable!();
            }
            Err(e) => Err(std::io::Error::new(std::io::ErrorKind::Other, e)),
        }
    }
    fn kill_process(&self, process_id: u32, signal: NodexSignal) -> Result<(), std::io::Error> {
        let signal = match signal {
            NodexSignal::SendFd => Signal::SIGUSR1,
            NodexSignal::Terminate => Signal::SIGTERM,
        };
        signal::kill(Pid::from_raw(process_id as i32), signal)
            .map_err(|e| std::io::Error::from_raw_os_error(e as _))
    }
}
