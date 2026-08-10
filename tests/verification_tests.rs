use kiss_daemon::config::AppConfig;
use kiss_daemon::engine::detector::DetectorEngine;
use kiss_daemon::engine::fallback::EngineOperatingMode;
use kiss_daemon::engine::heartbeat::BackgroundActivity;
use kiss_daemon::platform::{InputEvent, InputSource};
use std::time::Instant;

#[test]
fn test_config_parsing_full_partial_and_predicates() {
    // 1. Valid full config TOML
    let valid_toml = r#"
[allowlist]
allowed_x11_displays = ["X20", "X21"]
allowed_virtual_drivers = ["VirtualPS/2 VMware VMMouse"]
allowed_processes = ["/opt/google/chrome-remote-desktop/chrome-remote-desktop-host"]
"#;
    let config = AppConfig::parse(valid_toml).expect("Parsing valid TOML failed");
    assert!(config.is_display_allowed("X20"));
    assert!(config.is_display_allowed("X21"));
    assert!(!config.is_display_allowed("X0"));
    assert!(config.is_driver_allowed("VirtualPS/2 VMware VMMouse"));
    assert!(!config.is_driver_allowed("VirtualPS/2 Generic Mouse"));
    assert!(config.is_process_allowed("/opt/google/chrome-remote-desktop/chrome-remote-desktop-host"));

    // 2. Partial config (missing keys fall back cleanly to empty vectors)
    let partial_toml = r#"
[allowlist]
allowed_x11_displays = ["X20"]
"#;
    let partial_config = AppConfig::parse(partial_toml).expect("Parsing partial TOML failed");
    assert_eq!(partial_config.allowlist.allowed_x11_displays, vec!["X20"]);
    assert!(partial_config.allowlist.allowed_virtual_drivers.is_empty());
    assert!(partial_config.allowlist.allowed_processes.is_empty());

    // 3. Fall back to empty/default settings for invalid TOML
    let invalid_config = AppConfig::parse("bad_toml = [[[").unwrap_or_default();
    assert!(invalid_config.allowlist.allowed_x11_displays.is_empty());
}

#[test]
fn test_detector_config_exemption_virtual_driver() {
    let toml_str = r#"
[allowlist]
allowed_virtual_drivers = ["VirtualPS/2 VMware VMMouse"]
"#;
    let config = AppConfig::parse(toml_str).unwrap();
    let detector = DetectorEngine::with_config(15, config);
    detector.set_test_mode(true);
    detector.heartbeat.simulate_idle_seconds(20);

    let allowed_event = InputEvent {
        source: InputSource::SyntheticSoftware,
        pid: Some(1337),
        device_name: Some("VirtualPS/2 VMware VMMouse".into()),
        timestamp: Instant::now(),
    };

    let violation = detector.process_input_event(&allowed_event);
    assert!(
        violation.is_none(),
        "Input event from allowed virtual driver should be bypassed via config exemption"
    );
    assert!(
        !detector.is_isolation_triggered(),
        "Allowed virtual driver must not trigger isolation"
    );
}

#[test]
fn test_synthetic_input_triggers_isolation() {
    let detector = DetectorEngine::new(15);
    detector.set_test_mode(true);
    detector.heartbeat.simulate_idle_seconds(20);

    let synthetic_event = InputEvent {
        source: InputSource::SyntheticSoftware,
        pid: Some(1337),
        device_name: Some("Simulated Injection Device".into()),
        timestamp: Instant::now(),
    };

    let violation = detector.process_input_event(&synthetic_event);

    assert!(
        violation.is_some(),
        "Synthetic input during idle should return a violation report"
    );
    let rep = violation.unwrap();
    assert_eq!(rep.target_pid, Some(1337));
    assert!(rep.event_flags.contains(&"SYNTHETIC_INPUT_DURING_IDLE".to_string()));
    assert!(
        detector.is_isolation_triggered(),
        "Synthetic input should set isolation_triggered flag"
    );
}

#[test]
fn test_desktop_isolation_verification() {
    let detector = DetectorEngine::new(15);
    detector.set_test_mode(true);

    // Simulate custom desktop detection event processing
    let custom_desktop = "Test_HVNC_HiddenDesktop_01";
    let report = kiss_daemon::engine::ViolationReport {
        target_pid: Some(4096),
        desktop_identifier: Some(custom_desktop.into()),
        event_flags: vec![
            "HIDDEN_DESKTOP_DETECTED".into(),
            "HVNC_SESSION_FLAG".into(),
        ],
        description: format!("Test custom hidden desktop: {}", custom_desktop),
        timestamp: Instant::now(),
    };

    assert_eq!(report.desktop_identifier.as_deref(), Some(custom_desktop));
    assert!(report.event_flags.contains(&"HIDDEN_DESKTOP_DETECTED".to_string()));
}

#[test]
fn test_fallthrough_verification() {
    let detector = DetectorEngine::new(15);
    detector.set_test_mode(true);

    // 1. Deliberately revoke / force fallback mode
    detector.fallback.force_fallback(true);

    let (operating_mode, perm_status) = detector.fallback.determine_operating_mode();
    assert_eq!(
        operating_mode,
        EngineOperatingMode::HeartbeatDeltaFallback,
        "Engine should shift seamlessly to HeartbeatDeltaFallback mode when hook permissions are revoked"
    );
    assert!(!perm_status.hooks_available);
    assert!(perm_status.message.contains("Operating in Heartbeat Delta Analysis mode"));

    // 2. Verify Heartbeat Delta Analysis operates seamlessly in fallback mode without crashing
    detector.heartbeat.simulate_idle_seconds(20);

    let bg_activity = BackgroundActivity {
        pid: 2048,
        process_name: "obs_frame_capture".into(),
        has_framebuffer_capture: true,
        has_outbound_socket: true,
        timestamp: Instant::now(),
    };

    let violation = detector.register_background_activity(bg_activity);
    assert!(
        violation.is_some(),
        "Heartbeat Delta Engine should flag background process framebuffer/socket activity during physical idle"
    );
    let rep = violation.unwrap();
    assert_eq!(rep.target_pid, Some(2048));
    assert!(rep.event_flags.contains(&"HEARTBEAT_DELTA_VIOLATION".to_string()));
    assert!(
        detector.is_isolation_triggered(),
        "Heartbeat delta violation in fallback mode must trigger isolation state"
    );
}

#[test]
fn test_check_x11_sockets_allowlist() {
    use kiss_daemon::engine::detector::check_x11_sockets;

    let socket_dir = std::path::Path::new("/tmp/.X11-unix");
    let _ = std::fs::create_dir_all(socket_dir);
    let socket_path = socket_dir.join("X20");
    let created = std::fs::File::create(&socket_path).is_ok();

    if created {
        // 1. AppConfig containing "X20" in allowed_x11_displays
        let toml_allowed = r#"
[allowlist]
allowed_x11_displays = ["X20"]
"#;
        let config_allowed = AppConfig::parse(toml_allowed).expect("Failed to parse allowed config");
        let triggers = check_x11_sockets(&config_allowed);

        let x20_triggers: Vec<_> = triggers
            .iter()
            .filter(|t| t.desktop_identifier.as_deref() == Some("X20"))
            .collect();
        assert!(
            x20_triggers.is_empty(),
            "check_x11_sockets must return zero IsolationTrigger items for allowed display X20"
        );

        // 2. AppConfig without "X20" -> should flag X20 and return IsolationTrigger
        let config_unallowed = AppConfig::default();
        let triggers_unallowed = check_x11_sockets(&config_unallowed);
        let x20_unallowed_triggers: Vec<_> = triggers_unallowed
            .iter()
            .filter(|t| t.desktop_identifier.as_deref() == Some("X20"))
            .collect();
        assert_eq!(
            x20_unallowed_triggers.len(),
            1,
            "check_x11_sockets must return an IsolationTrigger item when X20 is not allowed"
        );

        let _ = std::fs::remove_file(&socket_path);
    }
}

#[test]
fn test_crostini_display_proxy_verification() {
    use kiss_daemon::engine::detector::check_x11_sockets;

    std::env::set_var("KISS_FORCE_CROSTINI", "1");

    let socket_dir = std::path::Path::new("/tmp/.X11-unix");
    let _ = std::fs::create_dir_all(socket_dir);
    let socket_x20 = socket_dir.join("X20");
    let socket_x1 = socket_dir.join("X1");
    let _ = std::fs::File::create(&socket_x20);
    let _ = std::fs::File::create(&socket_x1);

    // Clean install default AppConfig on Crostini
    let config = AppConfig::default();

    let triggers = check_x11_sockets(&config);
    let crostini_triggers: Vec<_> = triggers
        .iter()
        .filter(|t| {
            let id = t.desktop_identifier.as_deref().unwrap_or("");
            id == "X1" || id == "X20" || id == ":1" || id == ":20"
        })
        .collect();

    assert!(
        crostini_triggers.is_empty(),
        "Crostini Sommelier display proxy sockets X1 and X20 must be auto-exempted"
    );

    let _ = std::fs::remove_file(&socket_x20);
    let _ = std::fs::remove_file(&socket_x1);
    std::env::remove_var("KISS_FORCE_CROSTINI");
}

#[test]
fn test_sudo_user_config_path_priority() {
    let orig_home = std::env::var("HOME").ok();
    std::env::set_var("SUDO_USER", "testuser");
    std::env::set_var("HOME", "/root");

    let resolved_path = AppConfig::get_config_path();
    assert_eq!(
        resolved_path,
        std::path::PathBuf::from("/home/testuser/.kiss/config")
    );

    std::env::remove_var("SUDO_USER");
    if let Some(home) = orig_home {
        std::env::set_var("HOME", home);
    }
}

#[test]
fn test_crostini_network_isolation_execution() {
    std::env::set_var("KISS_FORCE_CROSTINI", "1");
    assert!(kiss_daemon::platform::is_crostini());
    // Executing killswitch in Crostini mode should use container-aware logic
    kiss_daemon::platform::execute_network_killswitch();
    std::env::remove_var("KISS_FORCE_CROSTINI");
}
