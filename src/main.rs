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
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;
    use windows_sys::Win32::Foundation::{HWND, LPARAM, LRESULT, WPARAM};
    use windows_sys::Win32::System::LibraryLoader::GetModuleHandleW;
    use windows_sys::Win32::System::StationsAndDesktops::{
        EnumDesktopsW, EnumWindowStationsW, GetProcessWindowStation, OpenWindowStationW,
    };
    use windows_sys::Win32::System::SystemInformation::GetTickCount64;
    use windows_sys::Win32::UI::Input::KeyboardAndMouse::{GetLastInputInfo, LASTINPUTINFO};
    use windows_sys::Win32::UI::Shell::{
        Shell_NotifyIconW, NOTIFYICONDATAW, NIF_ICON, NIF_MESSAGE, NIF_TIP, NIM_ADD,
    };
    use windows_sys::Win32::UI::WindowsAndMessaging::{
        AppendMenuW, CreatePopupMenu, CreateWindowExW, DefWindowProcW, DestroyMenu, GetCursorPos,
        LoadIconW, RegisterClassW, SetForegroundWindow, TrackPopupMenu,
        IDI_APPLICATION, MF_STRING, TPM_RIGHTBUTTON, WM_USER, WNDCLASSW,
    };

    const DESKTOP_ENUMERATE_ACCESS: u32 = 1;
    const WM_TRAYICON: u32 = WM_USER + 1;
    const IDM_TOGGLE_AFK: usize = 1001;
    const IDM_EXIT: usize = 1002;

    static mut IS_AFK_PTR: Option<Arc<AtomicBool>> = None;

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
        1
    }

    unsafe extern "system" fn enum_winsta_proc(lpsz_winsta: *const u16, lparam: LPARAM) -> i32 {
        if !lpsz_winsta.is_null() {
            let hwinsta = OpenWindowStationW(lpsz_winsta, 0, DESKTOP_ENUMERATE_ACCESS);
            if !hwinsta.is_null() {
                EnumDesktopsW(hwinsta, Some(enum_desktop_proc), lparam);
            }
        }
        1
    }

    pub fn scan_for_hidden_desktops() -> Result<Vec<String>, String> {
        let mut detected_desktops: Vec<String> = Vec::new();
        let lparam = &mut detected_desktops as *mut Vec<String> as LPARAM;

        unsafe {
            let win_station = GetProcessWindowStation();
            if !win_station.is_null() {
                EnumDesktopsW(win_station, Some(enum_desktop_proc), lparam);
            }
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

    unsafe extern "system" fn window_proc(
        hwnd: HWND,
        msg: u32,
        _wparam: WPARAM,
        lparam: LPARAM,
    ) -> LRESULT {
        if msg == WM_TRAYICON && (lparam as u32) == 0x0205 {
            let menu = CreatePopupMenu();
            let state_str = if let Some(ref afk) = IS_AFK_PTR {
                if afk.load(Ordering::SeqCst) {
                    "Disable AFK Mode\0"
                } else {
                    "Enable AFK Mode\0"
                }
            } else {
                "Toggle AFK Mode\0"
            };

            let state_utf16: Vec<u16> = state_str.encode_utf16().collect();
            let exit_utf16: Vec<u16> = "Exit\0".encode_utf16().collect();

            AppendMenuW(menu, MF_STRING, IDM_TOGGLE_AFK, state_utf16.as_ptr());
            AppendMenuW(menu, MF_STRING, IDM_EXIT, exit_utf16.as_ptr());

            let mut pt = std::mem::zeroed();
            GetCursorPos(&mut pt);
            SetForegroundWindow(hwnd);

            let cmd = TrackPopupMenu(
                menu,
                TPM_RIGHTBUTTON | 0x0100,
                pt.x,
                pt.y,
                0,
                hwnd,
                std::ptr::null(),
            );

            DestroyMenu(menu);

            if cmd as usize == IDM_TOGGLE_AFK {
                if let Some(ref afk) = IS_AFK_PTR {
                    let curr = afk.load(Ordering::SeqCst);
                    afk.store(!curr, Ordering::SeqCst);
                }
            } else if cmd as usize == IDM_EXIT {
                std::process::exit(0);
            }
            return 0;
        }
        DefWindowProcW(hwnd, msg, _wparam, lparam)
    }

    pub fn spawn_native_tray(is_afk: Arc<AtomicBool>) {
        unsafe {
            IS_AFK_PTR = Some(is_afk);

            let hinstance = GetModuleHandleW(std::ptr::null());
            let class_name: Vec<u16> = "KISS_Tray_Class\0".encode_utf16().collect();

            let wnd_class = WNDCLASSW {
                style: 0,
                lpfnWndProc: Some(window_proc),
                cbClsExtra: 0,
                cbWndExtra: 0,
                hInstance: hinstance,
                hIcon: LoadIconW(std::ptr::null_mut(), IDI_APPLICATION),
                hCursor: std::ptr::null_mut(),
                hbrBackground: std::ptr::null_mut(),
                lpszMenuName: std::ptr::null(),
                lpszClassName: class_name.as_ptr(),
            };

            RegisterClassW(&wnd_class);

            let hwnd = CreateWindowExW(
                0,
                class_name.as_ptr(),
                class_name.as_ptr(),
                0,
                0,
                0,
                0,
                0,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                hinstance,
                std::ptr::null(),
            );

            let mut nid: NOTIFYICONDATAW = std::mem::zeroed();
            nid.cbSize = std::mem::size_of::<NOTIFYICONDATAW>() as u32;
            nid.hWnd = hwnd;
            nid.uID = 1;
            nid.uFlags = NIF_ICON | NIF_MESSAGE | NIF_TIP;
            nid.uCallbackMessage = WM_TRAYICON;
            nid.hIcon = LoadIconW(std::ptr::null_mut(), IDI_APPLICATION);

            let tip: Vec<u16> = "KISS AV Security Daemon\0".encode_utf16().collect();
            for (i, &ch) in tip.iter().enumerate().take(128) {
                nid.szTip[i] = ch;
            }

            Shell_NotifyIconW(NIM_ADD, &nid);

            let mut msg = std::mem::zeroed();
            while windows_sys::Win32::UI::WindowsAndMessaging::GetMessageW(&mut msg, std::ptr::null_mut(), 0, 0) > 0 {
                windows_sys::Win32::UI::WindowsAndMessaging::TranslateMessage(&msg);
                windows_sys::Win32::UI::WindowsAndMessaging::DispatchMessageW(&msg);
            }
        }
    }
}

// =========================================================================
// LINUX PLATFORM IMPLEMENTATION (X11 & Wayland)
// =========================================================================
#[cfg(target_os = "linux")]
mod platform {
    use std::fs;
    use std::process::Command;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;

    pub fn scan_for_hidden_desktops() -> Result<Vec<String>, String> {
        let mut suspicious = Vec::new();

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
            std::thread::sleep(std::time::Duration::from_secs(2));
        }
    }
}

// =========================================================================
// MACOS PLATFORM IMPLEMENTATION
// =========================================================================
#[cfg(target_os = "macos")]
mod platform {
    use std::process::Command;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;

    pub fn scan_for_hidden_desktops() -> Result<Vec<String>, String> {
        let mut suspicious = Vec::new();

        let output = Command::new("pgrep").args(["-fl", "screensharingd"]).output();
        if let Ok(out) = output {
            let stdout = String::from_utf8_lossy(&out.stdout);
            if stdout.lines().count() > 1 {
                suspicious.push("Multiple active screensharingd sessions detected".into());
            }
        }

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
            std::thread::sleep(std::time::Duration::from_secs(10));
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
}

// =========================================================================
// MAIN CORE ENGINE
// =========================================================================
fn main() {
    let is_afk = Arc::new(AtomicBool::new(false));

    // Spawn platform-native tray interface
    let tray_afk = Arc::clone(&is_afk);
    thread::spawn(move || {
        platform::spawn_native_tray(tray_afk);
    });

    let mut last_activity_check = Instant::now();

    loop {
        // Condition 1: Scan for hidden VNC stations, secondary desktops, or listening sockets
        match platform::scan_for_hidden_desktops() {
            Ok(suspicious) => {
                if !suspicious.is_empty() {
                    platform::execute_network_killswitch();
                    break;
                }
            }
            Err(_e) => {}
        }

        // Condition 2: AFK State & Input Verification Check
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
}
