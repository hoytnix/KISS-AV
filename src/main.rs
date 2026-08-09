use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

// =========================================================================
// WINDOWS PLATFORM IMPLEMENTATION
// =========================================================================
#[cfg(target_os = "windows")]
mod platform {
    use std::ffi::OsString;
    use std::os::windows::ffi::OsStringExt;
    use windows_sys::Win32::Foundation::{LPARAM, TRUE};
    use windows_sys::Win32::System::StationsAndDesktops::{
        EnumDesktopsW, EnumWindowStationsW, GetProcessWindowStation, OpenWindowStationW,
    };
    use windows_sys::Win32::System::SystemInformation::GetTickCount64;
    use windows_sys::Win32::UI::Input::KeyboardAndMouse::{GetLastInputInfo, LASTINPUTINFO};

    // Constant for WINSTA_ENUMDESKTOPS (0x0001) to enumerate desktops on a window station
    const DESKTOP_ENUMERATE_ACCESS: u32 = 1;

    unsafe extern "system" fn enum_desktop_proc(lpsz_desktop: *const u16, lparam: LPARAM) -> i32 {
        if !lpsz_desktop.is_null() {
            let mut len = 0;
            while *lpsz_desktop.add(len) != 0 {
                len += 1;
            }
            let slice = std::slice::from_raw_parts(lpsz_desktop, len);
            let desktop_name = OsString::from_wide(slice).to_string_lossy().into_owned();

            let target_vec = &mut *(lparam as *mut Vec<String>);
            if !target_vec.contains(&desktop_name) {
                target_vec.push(desktop_name);
            }
        }
        TRUE
    }

    unsafe extern "system" fn enum_winsta_proc(lpsz_winsta: *const u16, lparam: LPARAM) -> i32 {
        if !lpsz_winsta.is_null() {
            let hwinsta = OpenWindowStationW(lpsz_winsta, 0, DESKTOP_ENUMERATE_ACCESS);
            if !hwinsta.is_null() {
                EnumDesktopsW(hwinsta, Some(enum_desktop_proc), lparam);
            }
        }
        TRUE
    }

    pub fn scan_for_hidden_desktops() -> Result<Vec<String>, String> {
        let mut detected_desktops: Vec<String> = Vec::new();
        let lparam = &mut detected_desktops as *mut Vec<String> as LPARAM;

        unsafe {
            // 1. Enumerate current process window station
            let win_station = GetProcessWindowStation();
            if !win_station.is_null() {
                EnumDesktopsW(win_station, Some(enum_desktop_proc), lparam);
            }

            // 2. Enumerate all window stations (catches hVNC / isolated services)
            EnumWindowStationsW(Some(enum_winsta_proc), lparam);
        }

        let suspicious = detected_desktops
            .into_iter()
            .filter(|name| {
                let n = name.to_lowercase();
                n != "default" && n != "winlogon" && n != "disconnect" && n != "screen-saver"
            })
            .collect();

        Ok(suspicious)
    }

    pub fn get_system_idle_time_secs() -> u64 {
        unsafe {
            let mut lii = LASTINPUTINFO {
                cbSize: std::mem::size_of::<LASTINPUTINFO>() as u32,
                dwTime: 0,
            };

            if GetLastInputInfo(&mut lii) != 0 {
                let uptime_ms = GetTickCount64();
                let last_input_ms = lii.dwTime as u64;
                if uptime_ms >= last_input_ms {
                    return (uptime_ms - last_input_ms) / 1000;
                }
            }
            0
        }
    }

    pub fn execute_network_killswitch() {
        let _ = std::process::Command::new("netsh")
            .args(["interface", "set", "interface", "Wi-Fi", "disable"])
            .status();
        let _ = std::process::Command::new("netsh")
            .args(["interface", "set", "interface", "Ethernet", "disable"])
            .status();
    }
}

// =========================================================================
// LINUX PLATFORM IMPLEMENTATION (X11 & Wayland)
// =========================================================================
#[cfg(target_os = "linux")]
mod platform {
    use std::fs;
    use std::process::Command;

    pub fn scan_for_hidden_desktops() -> Result<Vec<String>, String> {
        let mut suspicious = Vec::new();

        // 1. Process Command Line Checks
        if let Ok(entries) = fs::read_dir("/proc") {
            for entry in entries.flatten() {
                let path = entry.path().join("cmdline");
                if let Ok(cmdline) = fs::read_to_string(path) {
                    if cmdline.contains("Xvfb") || cmdline.contains("x11vnc") || cmdline.contains("tightvncserver") {
                        suspicious.push(cmdline.replace('\0', " "));
                    }
                }
            }
        }

        // 2. Open TCP Socket Inspection for VNC Ports (5900-5999 & 5800-5899)
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

        Ok(suspicious)
    }

    pub fn get_system_idle_time_secs() -> u64 {
        // Attempt X11 Query via xprintidle
        if let Ok(output) = Command::new("xprintidle").output() {
            if let Ok(s) = String::from_utf8(output.stdout) {
                if let Ok(ms) = s.trim().parse::<u64>() {
                    return ms / 1000;
                }
            }
        }

        // Fallback for Wayland via GNOME D-Bus IdleMonitor
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
}

// =========================================================================
// MACOS PLATFORM IMPLEMENTATION
// =========================================================================
#[cfg(target_os = "macos")]
mod platform {
    use std::process::Command;

    pub fn scan_for_hidden_desktops() -> Result<Vec<String>, String> {
        let mut suspicious = Vec::new();

        // 1. Process checks for secondary screensharing engines
        let output = Command::new("pgrep").args(["-fl", "screensharingd"]).output();
        if let Ok(out) = output {
            let stdout = String::from_utf8_lossy(&out.stdout);
            if stdout.lines().count() > 1 {
                suspicious.push("Multiple active screensharingd sessions detected".into());
            }
        }

        // 2. Network socket verification for VNC/RDP services
        let lsof_out = Command::new("lsof").args(["-i", ":5900"]).output();
        if let Ok(out) = lsof_out {
            let stdout = String::from_utf8_lossy(&out.stdout);
            if stdout.lines().count() > 1 {
                suspicious.push("Active VNC server listening on port 5900".into());
            }
        }

        Ok(suspicious)
    }

    pub fn get_system_idle_time_secs() -> u64 {
        // Query CoreGraphics HID idle time directly via ioreg
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
}

// =========================================================================
// MAIN CORE ENGINE
// =========================================================================
fn main() {
    // Daemon startup - running silently without console output
    let is_afk = Arc::new(AtomicBool::new(false));

    // AFK Mode Toggle Simulation (Triggers after 10 seconds)
    let afk_clone = Arc::clone(&is_afk);
    thread::spawn(move || {
        thread::sleep(Duration::from_secs(10));
        // AFK Guard Mode now active in background
        afk_clone.store(true, Ordering::SeqCst);
    });

    let mut last_activity_check = Instant::now();

    loop {
        // Initiating silent cross-platform security sweep

        // Condition 1: Scan for hidden VNC stations, secondary desktops, or listening sockets
        match platform::scan_for_hidden_desktops() {
            Ok(suspicious) => {
                if !suspicious.is_empty() {
                    // ALERT: Unauthorized background desktop or session detected
                    // ACTION: Disabling all network adapters immediately via killswitch
                    platform::execute_network_killswitch();
                    break;
                }
            }
            Err(_e) => {
                // Desktop enumeration error occurred silently
            }
        }

        // Condition 2: AFK State & Input Verification Check
        if is_afk.load(Ordering::SeqCst) {
            let idle_secs = platform::get_system_idle_time_secs();

            // Unexpected physical or synthetic activity detected during AFK mode
            if idle_secs < 4 && last_activity_check.elapsed().as_secs() >= 5 {
                // ALERT: Physical/Synthetic hardware input detected while locked in AFK mode
                // ACTION: Executing network cut
                platform::execute_network_killswitch();
                break;
            }
        }

        last_activity_check = Instant::now();
        thread::sleep(Duration::from_secs(5));
    }
}