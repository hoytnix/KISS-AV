pub mod detector;
pub mod fallback;
pub mod heartbeat;

pub use detector::{
    check_virtual_input_drivers, check_virtual_inputs, check_x11_sockets, run_checks,
    DetectorEngine, IsolationTrigger, ViolationReport,
};
pub use fallback::{EngineOperatingMode, FallbackManager};
pub use heartbeat::{BackgroundActivity, HeartbeatDeltaReport, HeartbeatEngine};
