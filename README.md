# Keep It Simple Stupid Antivirus (KISS-AV)

## KISS AV v2.1.2 Enterprise Edition

### Downloads

* **[Windows x64 Installer (.exe)](https://github.com/hoytnix/KISS-AV/releases/download/v2.1.2/kiss-daemon_2.1.2_x64-setup.exe)**
* **[macOS aarch64 Installer (.dmg)](https://github.com/hoytnix/KISS-AV/releases/download/v2.1.2/KissDaemon_2.1.2_aarch64.dmg)**
* **[Linux amd64 Package (.deb)](https://github.com/hoytnix/KISS-AV/releases/download/v2.1.2/kiss-daemon_2.1.2_amd64.deb)**
* **[Linux arm64 Package (.deb)](https://github.com/hoytnix/KISS-AV/releases/download/v2.1.2/kiss-daemon_2.1.2_arm64.deb)**

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

### 4. Robust TOML Allowlisting (`~/.kiss/config`)
- Multi-tier configuration path resolution: when running elevated (`sudo`), resolves the invoking user's config via `SUDO_USER` (`/home/{SUDO_USER}/.kiss/config`), falling back to `$HOME/.kiss/config`, and finally `/etc/kiss/config`.
- Gracefully falls back to default empty settings if no configuration file exists or fails to parse, preventing service disruption.
- Supports allowlisting for secondary X11 display sockets (matching formatted indices such as `X20`, `:20`, or `20`), virtual input drivers, and remote desktop processes.
- Outputs clear exemption logs to standard output when an anomaly is bypassed via configuration rules:
  ```text
  [CONFIG EXEMPTION] Allowed X11 display 'X20' via config allowlist
  [CONFIG EXEMPTION] Allowed virtual driver 'VirtualPS/2 VMware VMMouse' via config allowlist
  ```

---

## Configuration (`~/.kiss/config`)

KISS-AV can be customized using a TOML configuration file. Path resolution automatically resolves configuration in priority order:
1. `/home/{SUDO_USER}/.kiss/config` (if running with `sudo` / elevated privileges)
2. `$HOME/.kiss/config`
3. `/etc/kiss/config`

### Example Configuration:

```toml
[allowlist]
allowed_x11_displays = ["X20", "X21"]
allowed_virtual_drivers = ["VirtualPS/2 VMware VMMouse"]
allowed_processes = ["/opt/google/chrome-remote-desktop/chrome-remote-desktop-host"]
```

### Allowlist Fields:
- **`allowed_x11_displays`**: List of secondary X11 displays (e.g. `"X20"`, `":20"`, `"20"`) to permit without triggering network isolation.
- **`allowed_virtual_drivers`**: List of virtual software input drivers to allow.
- **`allowed_processes`**: List of remote desktop or screen capture process paths/executables to exempt.

---

## Project Architecture

```
src/
├── main.rs                 # Core service entry point & protection loop
├── lib.rs                  # Module re-export library
├── config.rs               # Strongly typed TOML configuration path resolution & allowlisting
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

KISS-AV includes automated verification tests covering synthetic input injection, hidden desktop detection, configuration parsing, allowlisting exemptions, and permission revocation fallthrough:

```bash
# Run all automated verification tests
cargo test
```

### Verification Scenarios Tested:
1. **Configuration Parsing & Exemption Verification:** Verifies full and partial TOML config parsing, multi-tier path resolution (`SUDO_USER`, `$HOME`, `/etc`), predicate matching, and DetectorEngine exemption bypassing.
2. **X11 Display Socket Allowlist Verification:** Confirms `check_x11_sockets` returns zero `IsolationTrigger` items for secondary sockets (e.g. `X20`) when present in `allowed_x11_displays`.
3. **Synthetic Input Verification:** Confirms that synthetic injection events trigger immediate network isolation when physical hardware is idle.
4. **Desktop Isolation Verification:** Confirms immediate detection of non-standard hidden desktops and isolation trigger.
5. **Fallthrough Verification:** Simulates revocation of hook permissions and confirms seamless transition to Heartbeat Delta Analysis mode without service interruption.

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
