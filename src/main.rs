use kiss_daemon::config::AppConfig;
use kiss_daemon::engine::detector::DetectorEngine;
use kiss_daemon::platform;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

fn main() {
    println!("Starting Enterprise-Grade KISS-AV Security Daemon...");

    // 0. Load Application Config
    let config = AppConfig::load();

    // 1. Elevated Execution & Privilege Check
    match platform::check_elevation() {
        Ok(elevated) => {
            if elevated {
                println!("[PRIVILEGE] Daemon running with elevated/root privileges.");
            } else {
                println!("[PRIVILEGE] Daemon running with standard privileges. Standard monitoring active.");
            }
        }
        Err(e) => {
            println!("[PRIVILEGE WARNING] Could not verify elevation status: {}", e);
        }
    }

    // 2. Initialize Engine & Fallback Architecture
    let detector = DetectorEngine::with_config(15, config.clone());
    let (operating_mode, perm_status) = detector.fallback.determine_operating_mode();
    println!(
        "[ENGINE MODE] Operating mode: {:?} - {}",
        operating_mode, perm_status.message
    );

    // 3. Initialize Input Event Receiver Channel
    let (event_sender, event_receiver) = mpsc::channel();

    // 4. Start OS Low-Level Input Hooks (if available)
    if let Some(_hook_thread) = platform::start_low_level_hooks(event_sender) {
        println!("[HOOKS] OS Low-Level Input Hooks initialized successfully.");
    } else {
        println!("[HOOKS FALLBACK] OS Low-Level Input Hooks unavailable or denied. Engine shifting to Heartbeat Delta Analysis.");
    }

    // 5. Spawn Native System Tray Interface
    let is_afk = Arc::new(AtomicBool::new(false));
    let tray_afk = Arc::clone(&is_afk);
    thread::spawn(move || {
        platform::spawn_native_tray(tray_afk);
    });

    // 6. Spawn Background Event Listener Thread
    let detector_event = detector.clone();
    thread::spawn(move || {
        while let Ok(event) = event_receiver.recv() {
            if let Some(violation) = detector_event.process_input_event(&event) {
                println!(
                    "[VIOLATION EVENT] Target PID: {:?}, Flags: {:?}",
                    violation.target_pid, violation.event_flags
                );
            }
        }
    });

    // 7. Main Core Sensor Audit & Isolation Loop
    println!("[CORE ENGINE] KISS-AV Protection Loop Active.");
    loop {
        let violations = detector.run_checks(&config);
        if !violations.is_empty() {
            println!(
                "[SECURITY BREACH] {} violations detected! Network isolation executed.",
                violations.len()
            );
            if detector.is_isolation_triggered() {
                println!("[SYSTEM ISOLATED] Airplane mode / Network killswitch active.");
            }
        }

        // Check AFK mode condition
        if is_afk.load(Ordering::SeqCst) {
            let idle_secs = platform::get_system_idle_time_secs();
            if idle_secs < 4 && detector.heartbeat.get_idle_duration().as_secs() >= 5 {
                println!("[AFK VIOLATION] Synthetic input detected while AFK!");
                platform::execute_network_killswitch();
                break;
            }
        }

        thread::sleep(Duration::from_secs(5));
    }
}
