# Keep It Simple Stupid Antivirus (KISS-AV)

## KISS AV v2.1.0 Enterprise Edition

### Downloads
* **[Windows x64 Installer (.exe)](https://github.com/hoytnix/KISS-AV/releases/download/v2.0.1/kiss-daemon_2.0.1_x64-setup.exe)**
* **[macOS aarch64 Installer (.dmg)](https://github.com/hoytnix/KISS-AV/releases/download/v2.0.1/KissDaemon_2.0.1_aarch64.dmg)**
* **[Linux amd64 Package (.deb)](https://github.com/hoytnix/KISS-AV/releases/download/v2.0.1/kiss-daemon_2.0.1_amd64.deb)**
* **[Linux arm64 Package (.deb)](https://github.com/hoytnix/KISS-AV/releases/download/v2.0.1/kiss-daemon_2.0.1_arm64.deb)**
=======
* **[Windows x64 Installer (.exe)](https://github.com/hoytnix/KISS-AV/releases/download/v2.1.0/kiss-daemon_2.1.0_x64-setup.exe)**
* **[macOS aarch64 Installer (.dmg)](https://github.com/hoytnix/KISS-AV/releases/download/v2.1.0/KissDaemon_2.1.0_aarch64.dmg)**
* **[Linux amd64 Package (.deb)](https://github.com/hoytnix/KISS-AV/releases/download/v2.1.0/kiss-daemon_2.1.0_amd64.deb)**

---

### Enterprise-Grade Security Engine

**KISS AV** is a thread-safe, obfuscated, cross-platform security daemon built in Rust. It actively detects hidden remote desktop sessions (HVNC, VNC, RDP), synthetic input injections, unauthorized hardware drivers, and background screen-scraping attempts while workstations are idle or locked.

When an anomaly is detected, KISS AV triggers a native network killswitch, instantly disabling Wi-Fi and Ethernet interfaces to prevent data exfiltration.

---

## Key Enterprise Features

### 1. Delta-Based Heartbeat Engine
- Tracks elapsed time since the last verified physical hardware input event.
- If physical hardware input registers zero for 15+ seconds while background processes execute active framebuffer captures or outbound socket connections, the engine flags the target process and triggers network isolation.

### 2. Isolation Trigger & Seamless Fallback Architecture
- Aggregates real-time detection events across OS platform sensors.
- **Graceful Hook Fallbacks:** If OS permissions are denied (e.g. macOS Accessibility API blocked or un-privileged Linux Wayland sessions), the daemon automatically falls back to Delta-Based Heartbeat Analysis without crashing the service.
- Logs comprehensive violation metadata including target PIDs, desktop identifiers, event flags, and timestamps.

### 3. OS Platform Sensor Architecture

#### Windows Architecture (`src/platform/windows.rs`)
- **Token Elevation Verification:** Checks current process token elevation (`OpenProcessToken` / `GetTokenInformation`).
- **Win32 Message Pump Isolation:** Low-level keyboard and mouse hooks (`WH_KEYBOARD_LL`, `WH_MOUSE_LL`) run on an isolated, dedicated thread with an explicit Win32 message pump (`GetMessageW` / `DispatchMessageW`) to prevent UI freezes under heavy system load.
- **Injection Flag Inspection:** Inspects `KBDLLHOOKSTRUCT` (`LLKHF_INJECTED`) and `MSLLHOOKSTRUCT` (`LLMHF_INJECTED`) for synthetic injection flags.
- **Raw Input Device Audit:** Cross-references input events against raw hardware device lists (`GetRawInputDeviceList`) to distinguish physical USB/Bluetooth drivers from virtual software input drivers.
- **Desktop Enumeration:** Traverses window stations (`EnumWindowStationsW` / `EnumDesktopsW`), excluding standard defaults (`Default`, `Winlogon`, `Disconnect`, `Screen-saver`) to detect hidden HVNC desktops.

#### macOS Architecture (`src/platform/macos.rs`)
- **Accessibility Trust Checks:** Queries process trust permissions (`AXIsProcessTrusted`). Prompts for permissions gracefully when denied and routes monitoring through the fallback engine.
- **SkyLight Display Spaces Audit:** Audits active desktop display spaces to catch hidden or secondary display spaces.
- **Event Tap Inspection:** Initializes `CGEventTap` to monitor incoming mouse/keyboard events, verifying target PIDs (`kCGEventTargetUnixProcessID`) and synthetic user data flags.

#### Linux Architecture (`src/platform/linux.rs`)
- **Input Device & Sysfs Audit:** Reads `/sys/class/input` and `/proc/bus/input/devices`, parsing vendor/product IDs, device names, and bus types (e.g. `BUS_USB`, `BUS_BLUETOOTH` vs `BUS_VIRTUAL` / `uinput`) to flag virtual input drivers.
- **X11 Unix Socket Scanning:** Audits `/tmp/.X11-unix/` for secondary display index sockets (e.g., `:1`, `:99`).
- **DBus Remote Desktop Auditing:** Queries DBus for active `RemoteDesktop` and `ScreenCast` portal sessions (`org.freedesktop.portal.Desktop`).

---

## Project Architecture

```
src/
├── main.rs                 # Core service entry point & protection loop
├── lib.rs                  # Module re-export library
├── engine/
│   ├── mod.rs              # Engine aggregator module
│   ├── detector.rs         # Core detection aggregator & isolation trigger
│   ├── fallback.rs         # OS hook fallback manager
│   └── heartbeat.rs        # Delta-based physical input heartbeat engine
└── platform/
    ├── mod.rs              # Platform abstraction layer & types
    ├── windows.rs          # Win32 elevated hooks, raw input, message pump thread
    ├── macos.rs            # macOS Accessibility check, SkyLight audit, CGEventTap
    └── linux.rs            # Linux sysfs input audit, X11 sockets, DBus portal check
```

---

## Verification & Automated Testing

KISS-AV includes automated verification tests covering synthetic input injection, hidden desktop detection, and permission revocation fallthrough:

```bash
# Run all automated verification tests
cargo test
```

### Verification Scenarios Tested:
1. **Synthetic Input Verification:** Confirms that synthetic injection events trigger immediate network isolation when physical hardware is idle.
2. **Desktop Isolation Verification:** Confirms immediate detection of non-standard hidden desktops and isolation trigger.
3. **Fallthrough Verification:** Simulates revocation of hook permissions and confirms seamless transition to Heartbeat Delta Analysis mode without service interruption.

---

## Building & Packaging

### Prerequisites
- Rust toolchain installed.
- `cargo-packager` installed:
  ```bash
  cargo install cargo-packager
  ```

### Build Command
To compile the release binary and generate native installers (.exe, .dmg, .deb):
```bash
cargo packager --release
```

Output installers will be placed in `target/release/`.

---

## License

This project is licensed under standard open-source terms. See the [LICENSE](LICENSE) file for details.
