use crate::config::AppConfig;
use crate::engine::fallback::FallbackManager;
use crate::engine::heartbeat::{BackgroundActivity, HeartbeatEngine};
use crate::platform::{self, InputEvent, InputSource};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Instant;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ViolationReport {
    pub target_pid: Option<u32>,
    pub desktop_identifier: Option<String>,
    pub event_flags: Vec<String>,
    pub description: String,
    pub timestamp: Instant,
}

pub type IsolationTrigger = ViolationReport;

pub fn check_x11_sockets(config: &AppConfig) -> Vec<IsolationTrigger> {
    let mut triggers = Vec::new();
    if let Ok(entries) = std::fs::read_dir("/tmp/.X11-unix") {
        for entry in entries.flatten() {
            let file_name = entry.file_name();
            let name_str = file_name.to_string_lossy();
            let trimmed = name_str.trim();

            let socket_num_opt: Option<u32> = if trimmed.starts_with('X') || trimmed.starts_with(':') {
                trimmed[1..].parse().ok()
            } else {
                trimmed.parse().ok()
            };

            if let Some(socket_num) = socket_num_opt {
                if socket_num > 2 {
                    let str_x = format!("X{}", socket_num);
                    let str_colon = format!(":{}", socket_num);
                    let str_num = socket_num.to_string();

                    if config.is_display_allowed(&str_x)
                        || config.is_display_allowed(&str_colon)
                        || config.is_display_allowed(&str_num)
                        || config.is_display_allowed(trimmed)
                    {
                        println!(
                            "[CONFIG EXEMPTION] Allowed X11 display '{}' via config allowlist",
                            str_x
                        );
                    } else {
                        triggers.push(ViolationReport {
                            target_pid: None,
                            desktop_identifier: Some(name_str.to_string()),
                            event_flags: vec![
                                "HIDDEN_DESKTOP_DETECTED".into(),
                                "HVNC_SESSION_FLAG".into(),
                            ],
                            description: format!(
                                "Non-standard hidden desktop session detected: Secondary X11 socket display index detected: {}",
                                name_str
                            ),
                            timestamp: Instant::now(),
                        });
                    }
                }
            }
        }
    }
    triggers
}

pub fn check_virtual_inputs(config: &AppConfig) -> Vec<IsolationTrigger> {
    let mut triggers = Vec::new();
    let devices = platform::audit_input_devices();
    for dev in devices {
        if dev.is_virtual {
            if config.is_driver_allowed(&dev.name) {
                println!(
                    "[CONFIG EXEMPTION] Allowed virtual driver '{}' via config allowlist",
                    dev.name
                );
            } else {
                triggers.push(ViolationReport {
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
                });
            }
        }
    }
    triggers
}

pub fn check_virtual_input_drivers(config: &AppConfig) -> Vec<IsolationTrigger> {
    check_virtual_inputs(config)
}

pub fn run_checks(config: &AppConfig) -> Vec<IsolationTrigger> {
    let mut triggers = check_x11_sockets(config);
    triggers.extend(check_virtual_inputs(config));
    triggers
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
                        "[CONFIG EXEMPTION] Allowed virtual driver '{}' via config allowlist",
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
                    "[CONFIG EXEMPTION] Allowed process '{}' via config allowlist",
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

    pub fn check_x11_sockets(&self, config: &AppConfig) -> Vec<IsolationTrigger> {
        let triggers = check_x11_sockets(config);
        for t in &triggers {
            self.trigger_isolation(t);
        }
        triggers
    }

    pub fn check_virtual_inputs(&self, config: &AppConfig) -> Vec<IsolationTrigger> {
        let triggers = check_virtual_inputs(config);
        for t in &triggers {
            self.trigger_isolation(t);
        }
        triggers
    }

    pub fn check_virtual_input_drivers(&self, config: &AppConfig) -> Vec<IsolationTrigger> {
        self.check_virtual_inputs(config)
    }

    pub fn run_checks(&self, config: &AppConfig) -> Vec<IsolationTrigger> {
        self.run_sensor_audit_with_config(config)
    }

    pub fn run_sensor_audit(&self) -> Vec<ViolationReport> {
        self.run_sensor_audit_with_config(&self.config)
    }

    pub fn run_sensor_audit_with_config(&self, config: &AppConfig) -> Vec<ViolationReport> {
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
                    let socket_num_opt: Option<u32> = if display.starts_with('X') || display.starts_with(':') {
                        display[1..].parse().ok()
                    } else {
                        display.parse().ok()
                    };

                    let is_allowed = if let Some(socket_num) = socket_num_opt {
                        let str_x = format!("X{}", socket_num);
                        let str_colon = format!(":{}", socket_num);
                        let str_num = socket_num.to_string();
                        config.is_display_allowed(&str_x)
                            || config.is_display_allowed(&str_colon)
                            || config.is_display_allowed(&str_num)
                            || config.is_display_allowed(display)
                    } else {
                        config.is_display_allowed(display)
                    };

                    if is_allowed {
                        let display_name = if let Some(sn) = socket_num_opt {
                            format!("X{}", sn)
                        } else {
                            display.to_string()
                        };
                        println!(
                            "[CONFIG EXEMPTION] Allowed X11 display '{}' via config allowlist",
                            display_name
                        );
                        continue;
                    }
                }

                // Extract process if applicable
                if let Some(cmd) = desktop.strip_prefix("Virtual Desktop Process: ") {
                    let cmd_trim = cmd.trim();
                    let first_arg = cmd_trim.split_whitespace().next().unwrap_or(cmd_trim);
                    if config.is_process_allowed(cmd_trim) || config.is_process_allowed(first_arg) {
                        println!(
                            "[CONFIG EXEMPTION] Allowed process '{}' via config allowlist",
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
                if config.is_driver_allowed(&dev.name) {
                    println!(
                        "[CONFIG EXEMPTION] Allowed virtual driver '{}' via config allowlist",
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
            if config.is_process_allowed(&dr.process_name) {
                println!(
                    "[CONFIG EXEMPTION] Allowed process '{}' via config allowlist",
                    dr.process_name
                );
                continue;
            }

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
