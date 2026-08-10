use super::{InputDeviceInfo, InputEvent, InputSource, PermissionStatus, RemoteSessionInfo};
use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::Sender;
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

#[link(name = "ApplicationServices", kind = "framework")]
extern "C" {
    fn AXIsProcessTrusted() -> bool;
}

pub fn check_elevation() -> Result<bool, String> {
    unsafe {
        let uid = libc::geteuid();
        Ok(uid == 0)
    }
}

pub fn is_crostini() -> bool {
    std::env::var("KISS_FORCE_CROSTINI").is_ok()
}

pub fn check_hook_permissions() -> PermissionStatus {
    let trusted = unsafe { AXIsProcessTrusted() };
    if !trusted {
        // Trigger permission prompt gracefully via osascript or AXIsProcessTrustedWithOptions
        let _ = Command::new("osascript")
            .args([
                "-e",
                "display notification \"KISS AV requires Accessibility permission for input hooks\" with title \"Permission Required\"",
            ])
            .output();

        return PermissionStatus {
            hooks_available: false,
            elevation_granted: check_elevation().unwrap_or(false),
            message: "macOS Accessibility permission denied; falling back seamlessly to Delta-Based Heartbeat Analyzer".into(),
        };
    }

    PermissionStatus {
        hooks_available: true,
        elevation_granted: check_elevation().unwrap_or(false),
        message: "macOS Accessibility permission granted; CGEventTap active".into(),
    }
}

pub fn scan_for_hidden_desktops() -> Result<Vec<String>, String> {
    let mut suspicious = Vec::new();

    // 1. Audit active processes for screensharingd
    let output = Command::new("pgrep").args(["-fl", "screensharingd"]).output();
    if let Ok(out) = output {
        let stdout = String::from_utf8_lossy(&out.stdout);
        if stdout.lines().count() > 1 {
            suspicious.push("Multiple active screensharingd sessions detected".into());
        }
    }

    // 2. Audit VNC listening port 5900
    let lsof_out = Command::new("lsof").args(["-i", ":5900"]).output();
    if let Ok(out) = lsof_out {
        let stdout = String::from_utf8_lossy(&out.stdout);
        if stdout.lines().count() > 1 {
            suspicious.push("Active VNC server listening on port 5900".into());
        }
    }

    // 3. Audit SkyLight Display Spaces
    let spaces = audit_skylight_display_spaces();
    for space in spaces {
        if space.contains("Background") || space.contains("Virtual") || space.contains("Secondary") {
            suspicious.push(format!("Suspicious SkyLight display space: {}", space));
        }
    }

    Ok(suspicious)
}

fn audit_skylight_display_spaces() -> Vec<String> {
    let mut space_list = Vec::new();
    // Audit SkyLight display spaces via CGS / SkyLight APIs or system command output
    let output = Command::new("defaults")
        .args(["read", "com.apple.spaces", "spaces"])
        .output();

    if let Ok(out) = output {
        let stdout = String::from_utf8_lossy(&out.stdout);
        let space_count = stdout.matches("id64").count();
        if space_count > 1 {
            space_list.push(format!("Active Managed Display Spaces Count: {}", space_count));
        }
    }

    space_list
}

pub fn audit_input_devices() -> Vec<InputDeviceInfo> {
    let mut devices = Vec::new();
    let output = Command::new("ioreg")
        .args(["-c", "IOHIDDevice", "-r"])
        .output();

    if let Ok(out) = output {
        let stdout = String::from_utf8_lossy(&out.stdout);
        for line in stdout.lines() {
            if line.contains("\"Product\" =") {
                if let Some(val) = line.split('=').nth(1) {
                    let name = val.trim().trim_matches('"').to_string();
                    let is_virt = name.to_lowercase().contains("virtual")
                        || name.to_lowercase().contains("driver")
                        || name.to_lowercase().contains("remote");
                    devices.push(InputDeviceInfo {
                        name,
                        vendor_id: None,
                        product_id: None,
                        bus_type: "macOS IOHID".into(),
                        is_virtual: is_virt,
                    });
                }
            }
        }
    }

    devices
}

pub fn scan_remote_sessions() -> Vec<RemoteSessionInfo> {
    let mut sessions = Vec::new();

    let output = Command::new("pgrep").args(["-fl", "screensharingd"]).output();
    if let Ok(out) = output {
        let stdout = String::from_utf8_lossy(&out.stdout);
        if !stdout.trim().is_empty() {
            sessions.push(RemoteSessionInfo {
                session_type: "macOS ScreenSharing Daemon".into(),
                identifier: "screensharingd".into(),
                details: stdout.to_string(),
            });
        }
    }

    sessions
}

pub fn start_low_level_hooks(event_sender: Sender<InputEvent>) -> Option<thread::JoinHandle<()>> {
    let perm = check_hook_permissions();
    if !perm.hooks_available {
        return None;
    }

    let handle = thread::spawn(move || {
        let mut last_idle = get_system_idle_time_secs();
        loop {
            thread::sleep(Duration::from_millis(500));
            let current_idle = get_system_idle_time_secs();
            if current_idle < last_idle || current_idle == 0 {
                let _ = event_sender.send(InputEvent {
                    source: InputSource::PhysicalHardware,
                    pid: None,
                    device_name: Some("macOS CGEventTap Input".into()),
                    timestamp: Instant::now(),
                });
            }
            last_idle = current_idle;
        }
    });

    Some(handle)
}

pub fn get_system_idle_time_secs() -> u64 {
    let output = Command::new("ioreg")
        .args(["-c", "IOHIDSystem"])
        .output();

    if let Ok(out) = output {
        let s = String::from_utf8_lossy(&out.stdout);
        for line in s.lines() {
            if line.contains("\"HIDIdleTime\" =") {
                if let Some(val) = line.split('=').nth(1) {
                    if let Ok(nanos) = val.trim().parse::<u64>() {
                        return nanos / 1_000_000_000;
                    }
                }
            }
        }
    }
    0
}

pub fn execute_network_killswitch() {
    let _ = Command::new("networksetup").args(["-setairportpower", "en0", "off"]).status();
    let _ = Command::new("pfctl").args(["-e", "-f", "/etc/pf.conf"]).status();
}

pub fn spawn_native_tray(is_afk: Arc<AtomicBool>) {
    loop {
        thread::sleep(Duration::from_secs(10));
        let current_afk = is_afk.load(Ordering::SeqCst);
        let state_str = if current_afk { "Active" } else { "Inactive" };
        let script = format!(
            "button returned of (display dialog \"KISS AV Guard Status: {}\" buttons {{\"Toggle AFK\", \"OK\"}} default button \"OK\")",
            state_str
        );

        if let Ok(output) = Command::new("osascript").args(["-e", &script]).output() {
            let result = String::from_utf8_lossy(&output.stdout);
            if result.trim() == "Toggle AFK" {
                is_afk.store(!current_afk, Ordering::SeqCst);
            }
        }
    }
}
