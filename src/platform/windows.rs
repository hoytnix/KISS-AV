use super::{InputDeviceInfo, InputEvent, InputSource, PermissionStatus, RemoteSessionInfo};
use std::ffi::OsString;
use std::os::windows::ffi::OsStringExt;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::Sender;
use std::sync::Arc;
use std::thread;
use std::time::Instant;

use windows_sys::Win32::Foundation::{HWND, LPARAM, LRESULT, WPARAM};
use windows_sys::Win32::Security::{GetTokenInformation, TokenElevation, TOKEN_QUERY};
use windows_sys::Win32::System::LibraryLoader::GetModuleHandleW;
use windows_sys::Win32::System::StationsAndDesktops::{
    EnumDesktopsW, EnumWindowStationsW, GetProcessWindowStation, OpenWindowStationW,
};
use windows_sys::Win32::System::SystemInformation::GetTickCount64;
use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
use windows_sys::Win32::UI::Input::KeyboardAndMouse::{GetLastInputInfo, LASTINPUTINFO};
use windows_sys::Win32::UI::Input::{
    GetRawInputDeviceList, RAWINPUTDEVICELIST, RIM_TYPEHID, RIM_TYPEKEYBOARD, RIM_TYPEMOUSE,
};
use windows_sys::Win32::UI::Shell::{
    Shell_NotifyIconW, NOTIFYICONDATAW, NIF_ICON, NIF_MESSAGE, NIF_TIP, NIM_ADD,
};
use windows_sys::Win32::UI::WindowsAndMessaging::{
    AppendMenuW, CallNextHookEx, CreatePopupMenu, CreateWindowExW, DefWindowProcW, DestroyMenu,
    DispatchMessageW, GetCursorPos, GetMessageW, LoadIconW, RegisterClassW, SetForegroundWindow,
    SetWindowsHookExW, TrackPopupMenu, TranslateMessage, UnhookWindowsHookEx, HHOOK, KBDLLHOOKSTRUCT,
    MSLLHOOKSTRUCT, WH_KEYBOARD_LL, WH_MOUSE_LL,
    IDI_APPLICATION, MF_STRING, TPM_RIGHTBUTTON, WM_USER, WNDCLASSW,
};

const WM_TRAYICON: u32 = WM_USER + 1;
const DESKTOP_ENUMERATE_ACCESS: u32 = 1;
const LLKHF_INJECTED: u32 = 0x10;
const LLMHF_INJECTED: u32 = 0x01;
const LLMHF_LOWER_IL_INJECTED: u32 = 0x02;

static mut EVENT_SENDER_PTR: Option<Sender<InputEvent>> = None;
static mut IS_AFK_PTR: Option<Arc<AtomicBool>> = None;

pub fn check_elevation() -> Result<bool, String> {
    unsafe {
        let mut handle = std::ptr::null_mut();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut handle) != 0 {
            let mut elevation: u32 = 0;
            let mut size: u32 = 0;
            let res = GetTokenInformation(
                handle,
                TokenElevation,
                &mut elevation as *mut u32 as *mut _,
                std::mem::size_of::<u32>() as u32,
                &mut size,
            );
            windows_sys::Win32::Foundation::CloseHandle(handle);
            if res != 0 {
                return Ok(elevation != 0);
            }
        }
    }
    Ok(false)
}

pub fn is_crostini() -> bool {
    std::env::var("KISS_FORCE_CROSTINI").is_ok()
}

pub fn check_hook_permissions() -> PermissionStatus {
    let is_elevated = check_elevation().unwrap_or(false);
    PermissionStatus {
        hooks_available: true,
        elevation_granted: is_elevated,
        message: if is_elevated {
            "Windows low-level input hooks available with elevated token".into()
        } else {
            "Windows low-level input hooks available (non-elevated token)".into()
        },
    }
}

unsafe extern "system" fn low_level_keyboard_proc(code: i32, wparam: WPARAM, lparam: LPARAM) -> LRESULT {
    if code >= 0 && lparam != 0 {
        let kbd_struct = *(lparam as *const KBDLLHOOKSTRUCT);
        let is_injected = (kbd_struct.flags & LLKHF_INJECTED) != 0;

        let source = if is_injected {
            InputSource::SyntheticSoftware
        } else {
            InputSource::PhysicalHardware
        };

        if let Some(ref sender) = EVENT_SENDER_PTR {
            let _ = sender.send(InputEvent {
                source,
                pid: None,
                device_name: Some("Win32 Keyboard Hook".into()),
                timestamp: Instant::now(),
            });
        }
    }
    CallNextHookEx(std::ptr::null_mut(), code, wparam, lparam)
}

unsafe extern "system" fn low_level_mouse_proc(code: i32, wparam: WPARAM, lparam: LPARAM) -> LRESULT {
    if code >= 0 && lparam != 0 {
        let mouse_struct = *(lparam as *const MSLLHOOKSTRUCT);
        let is_injected = (mouse_struct.flags & LLMHF_INJECTED) != 0
            || (mouse_struct.flags & LLMHF_LOWER_IL_INJECTED) != 0;

        let source = if is_injected {
            InputSource::SyntheticSoftware
        } else {
            InputSource::PhysicalHardware
        };

        if let Some(ref sender) = EVENT_SENDER_PTR {
            let _ = sender.send(InputEvent {
                source,
                pid: None,
                device_name: Some("Win32 Mouse Hook".into()),
                timestamp: Instant::now(),
            });
        }
    }
    CallNextHookEx(std::ptr::null_mut(), code, wparam, lparam)
}

pub fn start_low_level_hooks(event_sender: Sender<InputEvent>) -> Option<thread::JoinHandle<()>> {
    let perm = check_hook_permissions();
    if !perm.hooks_available {
        return None;
    }

    unsafe {
        EVENT_SENDER_PTR = Some(event_sender);
    }

    // Directives 3: WIN32 MESSAGE PUMP ISOLATION - Dedicated thread with explicit GetMessage / DispatchMessage loop
    let handle = thread::spawn(|| unsafe {
        let h_module = GetModuleHandleW(std::ptr::null());
        let kbd_hook: HHOOK = SetWindowsHookExW(
            WH_KEYBOARD_LL,
            Some(low_level_keyboard_proc),
            h_module,
            0,
        );
        let mouse_hook: HHOOK = SetWindowsHookExW(
            WH_MOUSE_LL,
            Some(low_level_mouse_proc),
            h_module,
            0,
        );

        if kbd_hook.is_null() && mouse_hook.is_null() {
            return;
        }

        let mut msg = std::mem::zeroed();
        while GetMessageW(&mut msg, std::ptr::null_mut(), 0, 0) > 0 {
            TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }

        if !kbd_hook.is_null() {
            UnhookWindowsHookEx(kbd_hook);
        }
        if !mouse_hook.is_null() {
            UnhookWindowsHookEx(mouse_hook);
        }
    });

    Some(handle)
}

pub fn audit_input_devices() -> Vec<InputDeviceInfo> {
    let mut devices = Vec::new();
    unsafe {
        let mut count: u32 = 0;
        GetRawInputDeviceList(
            std::ptr::null_mut(),
            &mut count,
            std::mem::size_of::<RAWINPUTDEVICELIST>() as u32,
        );

        if count > 0 {
            let mut raw_devices = vec![std::mem::zeroed::<RAWINPUTDEVICELIST>(); count as usize];
            if GetRawInputDeviceList(
                raw_devices.as_mut_ptr(),
                &mut count,
                std::mem::size_of::<RAWINPUTDEVICELIST>() as u32,
            ) != u32::MAX
            {
                for dev in raw_devices {
                    let dev_type_str = match dev.dwType {
                        RIM_TYPEMOUSE => "Mouse",
                        RIM_TYPEKEYBOARD => "Keyboard",
                        RIM_TYPEHID => "HID Device",
                        _ => "Unknown",
                    };
                    devices.push(InputDeviceInfo {
                        name: format!("Win32 Raw Input Device (Handle {:?})", dev.hDevice),
                        vendor_id: None,
                        product_id: None,
                        bus_type: dev_type_str.into(),
                        is_virtual: false,
                    });
                }
            }
        }
    }
    devices
}

pub fn scan_remote_sessions() -> Vec<RemoteSessionInfo> {
    let mut sessions = Vec::new();
    if let Ok(desktops) = scan_for_hidden_desktops() {
        for desktop in desktops {
            sessions.push(RemoteSessionInfo {
                session_type: "Hidden Win32 Desktop".into(),
                identifier: desktop.clone(),
                details: format!("Suspicious background desktop found: {}", desktop),
            });
        }
    }
    sessions
}

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

        AppendMenuW(menu, MF_STRING, 1001, state_utf16.as_ptr());
        AppendMenuW(menu, MF_STRING, 1002, exit_utf16.as_ptr());

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

        if cmd as usize == 1001 {
            if let Some(ref afk) = IS_AFK_PTR {
                let curr = afk.load(Ordering::SeqCst);
                afk.store(!curr, Ordering::SeqCst);
            }
        } else if cmd as usize == 1002 {
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
        while windows_sys::Win32::UI::WindowsAndMessaging::GetMessageW(
            &mut msg,
            std::ptr::null_mut(),
            0,
            0,
        ) > 0
        {
            windows_sys::Win32::UI::WindowsAndMessaging::TranslateMessage(&msg);
            windows_sys::Win32::UI::WindowsAndMessaging::DispatchMessageW(&msg);
        }
    }
}
