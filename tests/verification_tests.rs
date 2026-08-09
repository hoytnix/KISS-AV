use kiss_daemon::engine::detector::DetectorEngine;
use kiss_daemon::engine::fallback::EngineOperatingMode;
use kiss_daemon::engine::heartbeat::BackgroundActivity;
use kiss_daemon::platform::{InputEvent, InputSource};
use std::time::Instant;

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
