use crate::platform::InputEvent;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

#[derive(Debug, Clone)]
pub struct BackgroundActivity {
    pub pid: u32,
    pub process_name: String,
    pub has_framebuffer_capture: bool,
    pub has_outbound_socket: bool,
    pub timestamp: Instant,
}

#[derive(Debug, Clone)]
pub struct HeartbeatDeltaReport {
    pub target_pid: u32,
    pub process_name: String,
    pub idle_duration_secs: u64,
    pub has_framebuffer_capture: bool,
    pub has_outbound_socket: bool,
    pub is_violation: bool,
    pub flag_reason: String,
}

#[derive(Clone)]
pub struct HeartbeatEngine {
    last_physical_input: Arc<Mutex<Instant>>,
    last_synthetic_input: Arc<Mutex<Option<Instant>>>,
    recent_activities: Arc<Mutex<Vec<BackgroundActivity>>>,
    idle_threshold: Duration,
}

impl HeartbeatEngine {
    pub fn new(idle_threshold_secs: u64) -> Self {
        Self {
            last_physical_input: Arc::new(Mutex::new(Instant::now())),
            last_synthetic_input: Arc::new(Mutex::new(None)),
            recent_activities: Arc::new(Mutex::new(Vec::new())),
            idle_threshold: Duration::from_secs(idle_threshold_secs),
        }
    }

    pub fn record_physical_input(&self) {
        if let Ok(mut lock) = self.last_physical_input.lock() {
            *lock = Instant::now();
        }
    }

    pub fn simulate_idle_seconds(&self, secs: u64) {
        if let Ok(mut lock) = self.last_physical_input.lock() {
            *lock = Instant::now().checked_sub(Duration::from_secs(secs)).unwrap_or_else(Instant::now);
        }
    }

    pub fn record_synthetic_input(&self) {
        if let Ok(mut lock) = self.last_synthetic_input.lock() {
            *lock = Some(Instant::now());
        }
    }

    pub fn record_background_activity(&self, activity: BackgroundActivity) {
        if let Ok(mut lock) = self.recent_activities.lock() {
            lock.push(activity);
            // Retain recent activity entries from the last 60 seconds
            let now = Instant::now();
            lock.retain(|a| now.duration_since(a.timestamp) <= Duration::from_secs(60));
        }
    }

    pub fn process_input_event(&self, event: &InputEvent) {
        match event.source {
            crate::platform::InputSource::PhysicalHardware => {
                self.record_physical_input();
            }
            crate::platform::InputSource::SyntheticSoftware => {
                self.record_synthetic_input();
            }
            crate::platform::InputSource::Unknown => {}
        }
    }

    pub fn get_idle_duration(&self) -> Duration {
        if let Ok(lock) = self.last_physical_input.lock() {
            lock.elapsed()
        } else {
            Duration::from_secs(0)
        }
    }

    /// Evaluates heartbeat delta logic:
    /// If physical input registers zero for 15 or more seconds, but background processes
    /// execute framebuffer captures or outbound socket activity, flag the target process.
    pub fn evaluate_delta(&self) -> Vec<HeartbeatDeltaReport> {
        let mut reports = Vec::new();
        let idle_secs = self.get_idle_duration().as_secs();

        if idle_secs >= self.idle_threshold.as_secs() {
            if let Ok(activities) = self.recent_activities.lock() {
                for act in activities.iter() {
                    if act.has_framebuffer_capture || act.has_outbound_socket {
                        reports.push(HeartbeatDeltaReport {
                            target_pid: act.pid,
                            process_name: act.process_name.clone(),
                            idle_duration_secs: idle_secs,
                            has_framebuffer_capture: act.has_framebuffer_capture,
                            has_outbound_socket: act.has_outbound_socket,
                            is_violation: true,
                            flag_reason: format!(
                                "Physical input zero for {}s (>=15s), but target PID {} ({}) executed active framebuffer capture/outbound socket",
                                idle_secs, act.pid, act.process_name
                            ),
                        });
                    }
                }
            }
        }

        reports
    }
}
