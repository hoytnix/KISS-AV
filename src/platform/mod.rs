use std::time::Instant;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InputSource {
    PhysicalHardware,
    SyntheticSoftware,
    Unknown,
}

#[derive(Debug, Clone)]
pub struct InputEvent {
    pub source: InputSource,
    pub pid: Option<u32>,
    pub device_name: Option<String>,
    pub timestamp: Instant,
}

#[derive(Debug, Clone)]
pub struct PermissionStatus {
    pub hooks_available: bool,
    pub elevation_granted: bool,
    pub message: String,
}

#[derive(Debug, Clone)]
pub struct InputDeviceInfo {
    pub name: String,
    pub vendor_id: Option<u16>,
    pub product_id: Option<u16>,
    pub bus_type: String,
    pub is_virtual: bool,
}

#[derive(Debug, Clone)]
pub struct RemoteSessionInfo {
    pub session_type: String,
    pub identifier: String,
    pub details: String,
}

#[cfg(target_os = "windows")]
pub mod windows;
#[cfg(target_os = "windows")]
pub use windows as platform_impl;

#[cfg(target_os = "linux")]
pub mod linux;
#[cfg(target_os = "linux")]
pub use linux as platform_impl;

#[cfg(target_os = "macos")]
pub mod macos;
#[cfg(target_os = "macos")]
pub use macos as platform_impl;

pub use platform_impl::*;
