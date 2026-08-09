use crate::config::AppConfig;
use crate::engine::fallback::FallbackManager;
use crate::engine::heartbeat::{BackgroundActivity, HeartbeatEngine};
use crate::platform::{self, InputEvent, InputSource};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Instant;

#[derive(Debug, Clone)]
pub struct ViolationReport {
    pub target_pid: Option<u32>,
    pub desktop_identifier: Option<String>,
    pub event_flags: Vec<String>,
    pub description: String,
    pub timestamp: Instant,
}

#[derive(Clone)]
pub struct DetectorEngine {
    pub heartbeat: HeartbeatEngine,
    pub fallback: FallbackManager,
    pub isolation_triggered: Arc<AtomicBool>,
    pub test_mode: Arc<AtomicBool>,
    pub config: AppConfig,
}

impl DetectorEngine {
    pub fn new(heartbeat_threshold_secs: u64) -> Self {
        Self {
            heartbeat: HeartbeatEngine::new(heartbeat_threshold_secs),
            fallback: FallbackManager::new(),
            isolation_triggered: Arc::new(AtomicBool::new(false)),
            test_mode: Arc::new(AtomicBool::new(false)),
            config: AppConfig::load(),
        }
    }

    pub fn with_config(heartbeat_threshold_secs: u64, config: AppConfig) -> Self {
        Self {
            heartbeat: HeartbeatEngine::new(heartbeat_threshold_secs),
            fallback: FallbackManager::new(),
            isolation_triggered: Arc::new(AtomicBool::new(false)),
            test_mode: Arc::new(AtomicBool::new(false)),
            config,
        }
    }

    pub fn set_test_mode(&self, enabled: bool) {
        self.test_mode.store(enabled, Ordering::SeqCst);
    }

    pub fn is_isolation_triggered(&self) -> bool {
        self.isolation_triggered.load(Ordering::SeqCst)
    }

    pub fn reset_isolation_state(&self) {
        self.isolation_triggered.store(false, Ordering::SeqCst);
    }

    pub fn process_input_event(&self, event: &InputEvent) -> Option<ViolationReport> {
        self.heartbeat.process_input_event(event);

        // If event is synthetic and physical user has been idle (>= 15s or AFK)
        if event.source == InputSource::SyntheticSoftware {
            if let Some(ref dev_name) = event.device_name {
                if self.config.is_driver_allowed(dev_name) {
                    println!(
                        "[CONFIG EXEMPTION] Allowed virtual driver '{}' via ~/.kiss/config",
                        dev_name
                    );
                    return None;
                }
            }

            let idle_secs = self.heartbeat.get_idle_duration().as_secs();
            if idle_secs >= 15 || self.test_mode.load(Ordering::SeqCst) {
                let report = ViolationReport {
                    target_pid: event.pid,
                    desktop_identifier: None,
                    event_flags: vec![
                        "SYNTHETIC_INPUT_DURING_IDLE".into(),
                        "INJECTED_HOOK_FLAG".into(),
                    ],
                    description: format!(
                        "Synthetic input detected while physical hardware idle for {}s",
                        idle_secs
                    ),
                    timestamp: Instant::now(),
                };
                self.trigger_isolation(&report);
                return Some(report);
            }
        }
        None
    }

    pub fn register_background_activity(&self, activity: BackgroundActivity) -> Option<ViolationReport> {
        self.heartbeat.record_background_activity(activity);
        let delta_reports = self.heartbeat.evaluate_delta();

        if let Some(first) = delta_reports.first() {
            if self.config.is_process_allowed(&first.process_name) {
                println!(
                    "[CONFIG EXEMPTION] Allowed process '{}' via ~/.kiss/config",
                    first.process_name
                );
                return None;
            }

            let report = ViolationReport {
                target_pid: Some(first.target_pid),
                desktop_identifier: None,
                event_flags: vec![
                    "HEARTBEAT_DELTA_VIOLATION".into(),
                    "ACTIVE_SCREEN_SCRAPING_WHILE_IDLE".into(),
                ],
                description: first.flag_reason.clone(),
                timestamp: Instant::now(),
            };
            self.trigger_isolation(&report);
            return Some(report);
        }
        None
    }

    pub fn run_sensor_audit(&self) -> Vec<ViolationReport> {
        let mut reports = Vec::new();

        // 1. Audit hidden desktops & remote sessions
        if let Ok(hidden_desktops) = platform::scan_for_hidden_desktops() {
            for desktop in hidden_desktops {
                // Extract X11 display if applicable
                let display_opt = if let Some(disp) = desktop.strip_prefix("Secondary X11 socket display index detected: ") {
                    Some(disp.trim())
                } else if desktop.starts_with('X') && desktop != "X0" {
                    Some(desktop.as_str())
                } else {
                    None
                };

                if let Some(display) = display_opt {
                    if self.config.is_display_allowed(display) {
                        println!(
                            "[CONFIG EXEMPTION] Allowed X11 display '{}' via ~/.kiss/config",
                            display
                        );
                        continue;
                    }
                }

                // Extract process if applicable
                if let Some(cmd) = desktop.strip_prefix("Virtual Desktop Process: ") {
                    let cmd_trim = cmd.trim();
                    let first_arg = cmd_trim.split_whitespace().next().unwrap_or(cmd_trim);
                    if self.config.is_process_allowed(cmd_trim) || self.config.is_process_allowed(first_arg) {
                        println!(
                            "[CONFIG EXEMPTION] Allowed process '{}' via ~/.kiss/config",
                            first_arg
                        );
                        continue;
                    }
                }

                let report = ViolationReport {
                    target_pid: None,
                    desktop_identifier: Some(desktop.clone()),
                    event_flags: vec![
                        "HIDDEN_DESKTOP_DETECTED".into(),
                        "HVNC_SESSION_FLAG".into(),
                    ],
                    description: format!("Non-standard hidden desktop session detected: {}", desktop),
                    timestamp: Instant::now(),
                };
                self.trigger_isolation(&report);
                reports.push(report);
            }
        }

        // 2. Audit input devices for virtual software drivers
        let devices = platform::audit_input_devices();
        for dev in devices {
            if dev.is_virtual && self.heartbeat.get_idle_duration().as_secs() >= 15 {
                if self.config.is_driver_allowed(&dev.name) {
                    println!(
                        "[CONFIG EXEMPTION] Allowed virtual driver '{}' via ~/.kiss/config",
                        dev.name
                    );
                    continue;
                }

                let report = ViolationReport {
                    target_pid: None,
                    desktop_identifier: None,
                    event_flags: vec![
                        "VIRTUAL_INPUT_DRIVER_DETECTED".into(),
                        "UNAUTHORIZED_INJECTION_DEVICE".into(),
                    ],
                    description: format!(
                        "Virtual software input driver '{}' active while hardware user idle",
                        dev.name
                    ),
                    timestamp: Instant::now(),
                };
                self.trigger_isolation(&report);
                reports.push(report);
            }
        }

        // 3. Heartbeat Delta Analysis evaluation
        let delta_reports = self.heartbeat.evaluate_delta();
        for dr in delta_reports {
            let report = ViolationReport {
                target_pid: Some(dr.target_pid),
                desktop_identifier: None,
                event_flags: vec![
                    "HEARTBEAT_DELTA_VIOLATION".into(),
                    "BACKGROUND_SCRAPE_OR_SOCKET_WHILE_IDLE".into(),
                ],
                description: dr.flag_reason,
                timestamp: Instant::now(),
            };
            self.trigger_isolation(&report);
            reports.push(report);
        }

        reports
    }

    fn trigger_isolation(&self, report: &ViolationReport) {
        self.isolation_triggered.store(true, Ordering::SeqCst);
        println!(
            "[ISOLATION TRIGGERED] PID: {:?}, Desktop: {:?}, Flags: {:?}, Reason: {}",
            report.target_pid, report.desktop_identifier, report.event_flags, report.description
        );

        if !self.test_mode.load(Ordering::SeqCst) {
            platform::execute_network_killswitch();
        }
    }
}
