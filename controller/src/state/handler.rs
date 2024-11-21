use crate::managers::{
    agent::AgentManager,
    resource::ResourceManager,
    runtime::{RuntimeError, RuntimeManager, State},
};
use crate::state::{
    default::{DefaultError, DefaultState},
    rollback::{RollbackError, RollbackState},
    update::{UpdateError, UpdateState},
};
use std::sync::Arc;
use tokio::sync::Mutex;

#[derive(Debug, thiserror::Error)]
pub enum StateHandlerError {
    #[error("update failed: {0}")]
    Update(#[from] UpdateError),
    #[error("rollback failed: {0}")]
    Rollback(#[from] RollbackError),
    #[error("default failed: {0}")]
    Default(#[from] DefaultError),
    #[error("failed to get runtime info: {0}")]
    RuntimeInfo(#[from] RuntimeError),
}

pub struct StateHandler;

impl StateHandler {
    pub fn new() -> Self {
        Self {}
    }

    pub async fn handle(
        &self,
        runtime_manager: &Arc<RuntimeManager>,
        agent_manager: &Arc<Mutex<AgentManager>>,
    ) -> Result<(), StateHandlerError> {
        match runtime_manager.get_state()? {
            State::Update => {
                let resource_manager = ResourceManager::new();
                {
                    let update_state =
                        UpdateState::new(agent_manager, resource_manager, runtime_manager);

                    if let Err(e) = update_state.execute().await {
                        log::error!("Failed to update state: {}", e);
                        self.handle_update_failed(runtime_manager, e)?;
                    }
                }
            }
            State::Rollback => {
                let resource_manager = ResourceManager::new();
                let rollback_state =
                    RollbackState::new(agent_manager, &resource_manager, runtime_manager);
                rollback_state.execute().await?;
            }
            State::Default => {
                let default_state = DefaultState::new(agent_manager, runtime_manager);
                default_state.execute().await?;
            }
            _ => {
                log::info!("No state change required.");
            }
        }

        Ok(())
    }

    fn handle_update_failed(
        &self,
        runtime_manager: &Arc<RuntimeManager>,
        update_error: UpdateError,
    ) -> Result<(), StateHandlerError> {
        if update_error.requires_rollback() {
            runtime_manager
                .update_state(State::Rollback)
                .map_err(|runtime_err| {
                    log::error!(
                        "Failed to transition to Rollback state: {}. Original error: {}",
                        runtime_err,
                        update_error
                    );
                    StateHandlerError::RuntimeInfo(runtime_err)
                })?;

            log::info!("Successfully transitioned to Rollback state.");
        } else {
            log::warn!(
                "Skipping rollback state transition due to ignored update error: {}",
                update_error
            );
        }
        Err(StateHandlerError::Update(update_error))
    }
}

impl Default for StateHandler {
    fn default() -> Self {
        Self::new()
    }
}
