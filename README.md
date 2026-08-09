# Keep It Simple Stupid Antivirus

## KISS AV v1.2.5

### Downloads
* **[Windows x64 Installer (.exe)](https://github.com/hoytnix/KISS-AV/releases/download/v1.2.5/kiss-daemon_1.2.5_x64-setup.exe)**
* **[macOS aarch64 Installer (.dmg)](https://github.com/hoytnix/KISS-AV/releases/download/v1.2.5/KissDaemon_1.2.5_aarch64.dmg)**
* **[Linux amd64 Package (.deb)](https://github.com/hoytnix/KISS-AV/releases/download/v1.2.5/kiss-daemon_1.2.5_amd64.deb)**

Are you deploying unattended machines or sensitive workstations, only to worry about hidden remote access Trojans (RATs), unauthorized local input, or stealthy hVNC sessions? 

Standard security tools often leave their strings and detection logic exposed in plaintext. A basic disassembler is all an attacker needs to find your detection routines, patch them out, and bypass your alarms—leaving your system completely vulnerable to secondary desktop sessions (VNC/RDP) or spoofed hardware inputs.

Enter **KISS AV**. 

This is a fully standalone, thread-safe, obfuscated, cross-platform security engine built in Rust. It actively sweeps for hidden virtual desktops, unauthorized network sockets, and hardware interrupts while your system is designated as Away From Keyboard (AFK). When an anomaly is detected, it doesn't just write a log entry—it immediately triggers a localized network killswitch, neutralizing remote threats before data exfiltration can occur. 

Best of all, your core logic is shielded by macro-level control-flow obfuscation and string encryption via the `goldberg` crate, making reverse engineering a nightmare for bad actors.

## Core Features

*   **Zero-Dependency Native Installers:** Built with `cargo-packager` to distribute standalone binaries (.msi, .dmg, .deb) that require no pre-installed runtimes.
*   **Military-Grade Code Obfuscation:** Uses procedural macros to encrypt strings and mangle the control flow of the execution loop at compile-time.
*   **Multi-Station & Socket Inspection:** Traverses all active Windows WindowStations via safe context pointers, inspects `/proc/net/tcp` for active VNC listening ports (5800–5999), and flags unauthorized screen-sharing daemons.
*   **Cross-Compositor AFK Monitoring:** Queries low-level OS APIs and fallback pipelines (`GetLastInputInfo`, GNOME D-Bus `IdleMonitor`, `xprintidle`, and `IOHIDSystem`) to detect physical or synthetic hardware activity during locked states across modern desktop environments (X11, Wayland, macOS, Win32).
*   **Thread-Safe Architecture:** Eliminates global mutable state in favor of isolated context pointers and thread-local memory passing.
*   **Instant Network Isolation:** Executes a hard shutdown of Wi-Fi and Ethernet interfaces via native system commands (`netsh`, `nmcli`/`rfkill`, `networksetup`/`pfctl`) the millisecond a breach is confirmed.

---

## Contributing

Secure your endpoints today. Follow the instructions below to generate native installers for your operating system in a single command.

### Prerequisites

Ensure you have the Rust toolchain installed.

```bash
# Install the cross-platform packager
cargo install cargo-packager
```

### Building the Installers

To compile the daemon with full obfuscation optimizations and generate the installation packages, simply run:

```bash
cargo packager --release
```

Once the build process is complete, navigate to the `target/release/` directory. You will find your production-ready, highly secure installers ready for deployment across Windows, macOS, or Linux.

## Architecture Overview

KISS Security Daemon leverages conditional compilation (`#[cfg(target_os = "...")]`) to interact seamlessly with platform-specific APIs:

*   **Windows:** Traverses all system WindowStations using `EnumWindowStationsW` and `EnumDesktopsW` with thread-safe `LPARAM` state passing to catch hidden hVNC sessions, while monitoring idle state via `GetLastInputInfo`.
*   **Linux:** Dual-engine detection targeting both X11 and Wayland compositors. Combines `/proc` process command-line sweeps, socket port binding inspection (5800–5999), and GNOME Mutter `IdleMonitor` D-Bus fallbacks with `rfkill`/`nmcli` killswitch execution.
*   **macOS:** Monitors `screensharingd` instances, inspects network bindings for default VNC ports via `lsof`, and queries `IOHIDSystem` for hardware idle times, isolating interfaces via `networksetup` and `pfctl`.

## License

This project is licensed under standard open-source terms. See the LICENSE file for details.
