use crate::platform::{self, PermissionStatus};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EngineOperatingMode {
    ActiveLowLevelHooks,
    HeartbeatDeltaFallback,
}

#[derive(Clone)]
pub struct FallbackManager {
    is_fallback_forced: Arc<AtomicBool>,
}

impl FallbackManager {
    pub fn new() -> Self {
        Self {
            is_fallback_forced: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Deliberately force hook fallback for verification/testing or permission revocation simulation
    pub fn force_fallback(&self, force: bool) {
        self.is_fallback_forced.store(force, Ordering::SeqCst);
    }

    /// Returns whether fallback mode is currently active
    pub fn is_fallback_active(&self) -> bool {
        if self.is_fallback_forced.load(Ordering::SeqCst) {
            return true;
        }
        let perm = platform::check_hook_permissions();
        !perm.hooks_available
    }

    /// Evaluates current OS permissions and resolves current operating mode
    pub fn determine_operating_mode(&self) -> (EngineOperatingMode, PermissionStatus) {
        let perm = platform::check_hook_permissions();

        if self.is_fallback_forced.load(Ordering::SeqCst) || !perm.hooks_available {
            (
                EngineOperatingMode::HeartbeatDeltaFallback,
                PermissionStatus {
                    hooks_available: false,
                    elevation_granted: perm.elevation_granted,
                    message: if self.is_fallback_forced.load(Ordering::SeqCst) {
                        "Hook permissions revoked/forced fallback. Operating in Heartbeat Delta Analysis mode.".into()
                    } else {
                        perm.message
                    },
                },
            )
        } else {
            (EngineOperatingMode::ActiveLowLevelHooks, perm)
        }
    }
}
