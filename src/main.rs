use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};
use goldberg::{goldberg_stmts, goldberg_string};

// =========================================================================
// WINDOWS PLATFORM IMPLEMENTATION
// =========================================================================
#[cfg(target_os = "windows")]
mod platform {
    use std::ffi::OsString;
    use std::os::windows::ffi::OsStringExt;
    use windows_sys::Win32::Foundation::{BOOL, LPARAM, PWSTR};
    use windows_sys::Win32::System::StationsAndDesktops::{
        EnumDesktopsW, GetProcessWindowStation,
    };
    use windows_sys::Win32::System::SystemInformation::GetTickCount64;
    use windows_sys::Win32::UI::Input::KeyboardAndMouse::{GetLastInputInfo, LASTINPUTINFO};

    static mut DETECTED_DESKTOPS: Vec<String> = Vec::new();

    unsafe extern "system" fn enum_desktop_proc(lpsz_desktop: PWSTR, _lparam: LPARAM) -> BOOL {
        if !lpsz_desktop.is_null() {
            let mut len = 0;
            while *lpsz_desktop.add(len) != 0 {
                len += 1;
            }
            let slice = std::slice::from_raw_parts(lpsz_desktop, len);
            let desktop_name = OsString::from_wide(slice).to_string_lossy().into_owned();
            DETECTED_DESKTOPS.push(desktop_name);
        }
        1
    }

    pub fn scan_for_hidden_desktops() -> Result<Vec<String>, String> {
        unsafe {
            DETECTED_DESKTOPS.clear();
            let win_station = GetProcessWindowStation();
            if win_station == 0 {
                return Err("Failed to obtain Process Window Station handle.".into());
            }

            if EnumDesktopsW(win_station, Some(enum_desktop_proc), 0) == 0 {
                return Err("EnumDesktopsW call failed.".into());
            }

            let suspicious: Vec<String> = DETECTED_DESKTOPS
                .iter()
                .filter(|&name| {
                    let n = name.to_lowercase();
                    n != "default" && n != "winlogon" && n != "disconnect" && n != "screen-saver"
                })
                .cloned()
                .collect();

            Ok(suspicious)
        }
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
// DEBIAN LINUX PLATFORM IMPLEMENTATION
// =========================================================================
#[cfg(target_os = "linux")]
mod platform {
    use std::fs;
    use std::process::Command;

    pub fn scan_for_hidden_desktops() -> Result<Vec<String>, String> {
        let mut suspicious = Vec::new();

        // Check for active virtual display servers like Xvfb, VNC, or X11rdp running in /proc
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
        Ok(suspicious)
    }

    pub fn get_system_idle_time_secs() -> u64 {
        // Queries xprintidle (X11 idle timer in ms) or falls back to reading /dev/input event modification times
        let output = Command::new("xprintidle").output();
        if let Ok(out) = output {
            if let Ok(s) = String::from_utf8(out.stdout) {
                if let Ok(ms) = s.trim().parse::<u64>() {
                    return ms / 1000;
                }
            }
        }
        0
    }

    pub fn execute_network_killswitch() {
        // Block all wireless and ethernet adapters using kernel rfkill and NetworkManager
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

        // Check process list for background VNC/Screen Sharing instances spawned outside standard system agents
        let output = Command::new("pgrep").args(["-fl", "screensharingd"]).output();
        if let Ok(out) = output {
            let stdout = String::from_utf8_lossy(&out.stdout);
            if stdout.lines().count() > 1 {
                suspicious.push("Multiple active screensharingd sessions detected".into());
            }
        }
        Ok(suspicious)
    }

    pub fn get_system_idle_time_secs() -> u64 {
        // Query macOS system idle time via ioreg (CoreGraphicsHIDEventTap)
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
        // Disable Wi-Fi and turn off active network services via networksetup
        let _ = Command::new("networksetup").args(["-setairportpower", "en0", "off"]).status();
        let _ = Command::new("pfctl").args(["-e", "-f", "/etc/pf.conf"]).status();
    }
}

// =========================================================================
// MAIN CORE ENGINE
// =========================================================================
fn main() {
    // Strings are encrypted at compile time so they don't show up in a hex editor
    let start_msg = goldberg_string!("=== KISS Security Daemon Engine Starting ===");
    println!("{}", start_msg);

    let is_afk = Arc::new(AtomicBool::new(false));

    // Simulation: Automatically toggle AFK mode after 10 seconds
    let afk_clone = Arc::clone(&is_afk);
    thread::spawn(move || {
        thread::sleep(Duration::from_secs(10));
        afk_clone.store(true, Ordering::SeqCst);
    });

    let mut last_activity_check = Instant::now();

    // The main execution flow is obfuscated here
    goldberg_stmts! {
        loop {
            let sweep_msg = goldberg_string!("[*] Performing 5-second cross-platform security sweep...");
            println!("{}", sweep_msg);

            // Condition 2: Hidden VNC / Secondary Session Inspection
            match platform::scan_for_hidden_desktops() {
                Ok(suspicious_desktops) => {
                    if !suspicious_desktops.is_empty() {
                        platform::execute_network_killswitch();
                        break;
                    }
                }
                Err(e) => eprintln!("[ERROR] Desktop enumeration error: {}", e),
            }

            // Condition 1: AFK Hardware Activity Verification
            if is_afk.load(Ordering::SeqCst) {
                let idle_secs = platform::get_system_idle_time_secs();

                if idle_secs < 4 && last_activity_check.elapsed().as_secs() >= 5 {
                    platform::execute_network_killswitch();
                    break;
                }
            }

            last_activity_check = Instant::now();
            thread::sleep(Duration::from_secs(5));
        }
    };
}