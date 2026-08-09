use super::{InputDeviceInfo, InputEvent, InputSource, PermissionStatus, RemoteSessionInfo};
use std::fs;
use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::Sender;
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

pub fn check_elevation() -> Result<bool, String> {
    unsafe {
        let uid = libc::geteuid();
        Ok(uid == 0)
    }
}

pub fn check_hook_permissions() -> PermissionStatus {
    let elevation = check_elevation().unwrap_or(false);
    let mut dev_readable = false;

    if let Ok(entries) = fs::read_dir("/dev/input") {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.to_string_lossy().contains("event") {
                if fs::File::open(&path).is_ok() {
                    dev_readable = true;
                    break;
                }
            }
        }
    }

    let is_wayland = std::env::var("WAYLAND_DISPLAY").is_ok();
    let hooks_available = dev_readable || (!is_wayland && elevation);

    PermissionStatus {
        hooks_available,
        elevation_granted: elevation,
        message: if hooks_available {
            "Linux input hook permission granted".into()
        } else {
            "Linux input hook permissions denied or un-privileged Wayland; falling back to Heartbeat Delta Engine".into()
        },
    }
}

pub fn scan_for_hidden_desktops() -> Result<Vec<String>, String> {
    let mut suspicious = Vec::new();

    // 1. Audit /proc for hidden virtual desktop & remote desktop processes
    if let Ok(entries) = fs::read_dir("/proc") {
        for entry in entries.flatten() {
            let path = entry.path().join("cmdline");
            if let Ok(cmdline) = fs::read_to_string(path) {
                if cmdline.contains("Xvfb")
                    || cmdline.contains("x11vnc")
                    || cmdline.contains("tightvncserver")
                    || cmdline.contains("tigervnc")
                    || cmdline.contains("xrdp")
                {
                    suspicious.push(format!("Virtual Desktop Process: {}", cmdline.replace('\0', " ")));
                }
            }
        }
    }

    // 2. Audit VNC listening ports
    for path in &["/proc/net/tcp", "/proc/net/tcp6"] {
        if let Ok(content) = fs::read_to_string(path) {
            for line in content.lines().skip(1) {
                let fields: Vec<&str> = line.split_whitespace().collect();
                if fields.len() > 1 {
                    if let Some(port_hex) = fields[1].split(':').nth(1) {
                        if let Ok(port) = u16::from_str_radix(port_hex, 16) {
                            if (5900..=5999).contains(&port) || (5800..=5899).contains(&port) {
                                suspicious.push(format!("Active VNC listening port detected: {}", port));
                            }
                        }
                    }
                }
            }
        }
    }

    // 3. Scan X11 unix sockets for secondary display indices (e.g., :1, :99)
    if let Ok(entries) = fs::read_dir("/tmp/.X11-unix") {
        for entry in entries.flatten() {
            let file_name = entry.file_name();
            let name_str = file_name.to_string_lossy();
            if name_str.starts_with('X') && name_str != "X0" {
                suspicious.push(format!("Secondary X11 socket display index detected: {}", name_str));
            }
        }
    }

    Ok(suspicious)
}

pub fn audit_input_devices() -> Vec<InputDeviceInfo> {
    let mut devices = Vec::new();

    if let Ok(content) = fs::read_to_string("/proc/bus/input/devices") {
        let mut current_name = String::new();
        let mut current_bus = String::new();
        let mut current_vendor: Option<u16> = None;
        let mut current_product: Option<u16> = None;

        for line in content.lines() {
            if line.starts_with("N: Name=") {
                current_name = line.trim_start_matches("N: Name=").trim_matches('"').to_string();
            } else if line.starts_with("I: Bus=") {
                // Example line: I: Bus=0003 Vendor=046d Product=c52b Version=0111
                for part in line.split_whitespace() {
                    if let Some(val) = part.strip_prefix("Bus=") {
                        current_bus = val.to_string();
                    } else if let Some(val) = part.strip_prefix("Vendor=") {
                        current_vendor = u16::from_str_radix(val, 16).ok();
                    } else if let Some(val) = part.strip_prefix("Product=") {
                        current_product = u16::from_str_radix(val, 16).ok();
                    }
                }
            } else if line.is_empty() {
                if !current_name.is_empty() {
                    let name_lower = current_name.to_lowercase();
                    let is_virt_bus = current_bus == "0006" || current_bus == "0000";
                    let is_virt_name = name_lower.contains("uinput")
                        || name_lower.contains("vmmouse")
                        || name_lower.contains("xdotool")
                        || name_lower.contains("ydotool")
                        || name_lower.contains("virtual");

                    devices.push(InputDeviceInfo {
                        name: current_name.clone(),
                        vendor_id: current_vendor,
                        product_id: current_product,
                        bus_type: current_bus.clone(),
                        is_virtual: is_virt_bus || is_virt_name,
                    });
                }
                current_name.clear();
                current_bus.clear();
                current_vendor = None;
                current_product = None;
            }
        }
    }

    devices
}

pub fn scan_remote_sessions() -> Vec<RemoteSessionInfo> {
    let mut sessions = Vec::new();

    // 1. Scan X11 Sockets
    if let Ok(entries) = fs::read_dir("/tmp/.X11-unix") {
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().into_owned();
            if name.starts_with('X') && name != "X0" {
                sessions.push(RemoteSessionInfo {
                    session_type: "X11 Secondary Socket".into(),
                    identifier: name.clone(),
                    details: format!("Found X11 unix socket at /tmp/.X11-unix/{}", name),
                });
            }
        }
    }

    // 2. Query DBus for active RemoteDesktop / ScreenCast sessions
    let dbus_check = Command::new("gdbus")
        .args([
            "call",
            "--session",
            "--dest",
            "org.freedesktop.portal.Desktop",
            "--object-path",
            "/org/freedesktop/portal/desktop",
            "--method",
            "org.freedesktop.DBus.Properties.Get",
            "org.freedesktop.portal.RemoteDesktop",
            "version",
        ])
        .output();

    if let Ok(out) = dbus_check {
        let stdout = String::from_utf8_lossy(&out.stdout);
        if stdout.contains("uint32") {
            sessions.push(RemoteSessionInfo {
                session_type: "Freedesktop RemoteDesktop Portal".into(),
                identifier: "org.freedesktop.portal.RemoteDesktop".into(),
                details: "RemoteDesktop DBus Portal service active".into(),
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
        // Event monitoring loop if permissions permit
        let mut last_idle = get_system_idle_time_secs();
        loop {
            thread::sleep(Duration::from_millis(500));
            let current_idle = get_system_idle_time_secs();
            if current_idle < last_idle || current_idle == 0 {
                let _ = event_sender.send(InputEvent {
                    source: InputSource::PhysicalHardware,
                    pid: None,
                    device_name: Some("Linux Physical Input".into()),
                    timestamp: Instant::now(),
                });
            }
            last_idle = current_idle;
        }
    });

    Some(handle)
}

pub fn get_system_idle_time_secs() -> u64 {
    if let Ok(output) = Command::new("xprintidle").output() {
        if let Ok(s) = String::from_utf8(output.stdout) {
            if let Ok(ms) = s.trim().parse::<u64>() {
                return ms / 1000;
            }
        }
    }

    let dbus_output = Command::new("gdbus")
        .args([
            "call",
            "--session",
            "--dest",
            "org.gnome.Mutter.IdleMonitor",
            "--object-path",
            "/org/gnome/Mutter/IdleMonitor/Core",
            "--method",
            "org.gnome.Mutter.IdleMonitor.GetIdletime",
        ])
        .output();

    if let Ok(out) = dbus_output {
        let s = String::from_utf8_lossy(&out.stdout);
        if let Some(start) = s.find("uint64 ") {
            let rest = &s[start + 7..];
            if let Some(end) = rest.find(|c: char| !c.is_ascii_digit()) {
                if let Ok(ms) = rest[..end].parse::<u64>() {
                    return ms / 1000;
                }
            }
        }
    }

    0
}

pub fn execute_network_killswitch() {
    let _ = Command::new("rfkill").args(["block", "all"]).status();
    let _ = Command::new("nmcli").args(["networking", "off"]).status();
}

pub fn spawn_native_tray(is_afk: Arc<AtomicBool>) {
    let mut last_state = is_afk.load(Ordering::SeqCst);
    loop {
        let current_state = is_afk.load(Ordering::SeqCst);
        if current_state != last_state {
            let status_msg = if current_state {
                "KISS AV: AFK Guard Enabled"
            } else {
                "KISS AV: AFK Guard Disabled"
            };

            let _ = Command::new("gdbus")
                .args([
                    "call",
                    "--session",
                    "--dest",
                    "org.freedesktop.Notifications",
                    "--object-path",
                    "/org/freedesktop/Notifications",
                    "--method",
                    "org.freedesktop.Notifications.Notify",
                    "KISS AV",
                    "0",
                    "security-high",
                    "KISS Security Daemon",
                    status_msg,
                    "[]",
                    "{}",
                    "3000",
                ])
                .status();

            last_state = current_state;
        }
        std::thread::sleep(Duration::from_secs(2));
    }
}
