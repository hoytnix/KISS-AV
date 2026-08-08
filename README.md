# Keep It Simple Stupid Antivirus

## KISS AV v1.1.7

Are you deploying unattended machines or sensitive workstations, only to worry about hidden remote access Trojans (RATs) or unauthorized local input? 

Standard security tools often leave their strings and detection logic exposed in plaintext. A basic disassembler is all an attacker needs to find your detection routines, patch them out, and bypass your alarms—leaving your system completely vulnerable to secondary desktop sessions (VNC/RDP) or spoofed hardware inputs.

Enter **KISS AV**. 

This is a fully standalone, obfuscated, cross-platform security engine built in Rust. It actively sweeps for hidden virtual desktops and unauthorized hardware interrupts while your system is designated as Away From Keyboard (AFK). When an anomaly is detected, it doesn't just write a log entry—it immediately triggers a localized network killswitch, neutralizing remote threats before data exfiltration can occur. 

Best of all, your core logic is shielded by macro-level control-flow obfuscation and string encryption via the `goldberg` crate, making reverse engineering a nightmare for bad actors.

## Core Features

*   **Zero-Dependency Native Installers:** Built with `cargo-packager` to distribute standalone binaries (.msi, .dmg, .deb) that require no pre-installed runtimes.
*   **Military-Grade Code Obfuscation:** Uses procedural macros to encrypt strings and mangle the control flow of the execution loop at compile-time.
*   **Hidden Desktop Detection:** Scans for unauthorized window stations, secondary X11/VNC servers, and hidden screen-sharing daemons.
*   **AFK Hardware Monitoring:** Queries low-level OS APIs (LASTINPUTINFO, xprintidle, IOHIDSystem) to ensure no physical or spoofed hardware inputs occur while the system is locked.
*   **Instant Network Isolation:** Executes a hard shutdown of Wi-Fi and Ethernet interfaces via native system commands (`netsh`, `nmcli`, `networksetup`) the millisecond a breach is confirmed.

---

## Getting Started

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

*   **Windows:** Interacts with `Win32::System::StationsAndDesktops` and `Win32::UI::Input` to monitor hidden window stations.
*   **Linux:** Parses `/proc` for hidden virtual framebuffers (Xvfb, VNC) and hooks into `xprintidle` / `rfkill`.
*   **macOS:** Monitors `screensharingd` instances and queries `IOHIDSystem` for true hardware idle times, isolating via `pfctl` and `networksetup`.

## License

This project is licensed under standard open-source terms. See the LICENSE file for details.
