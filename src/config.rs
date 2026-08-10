use serde::Deserialize;
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Default, Deserialize, PartialEq, Eq)]
pub struct AllowlistConfig {
    #[serde(default)]
    pub allowed_x11_displays: Vec<String>,
    #[serde(default)]
    pub allowed_virtual_drivers: Vec<String>,
    #[serde(default)]
    pub allowed_processes: Vec<String>,
}

#[derive(Debug, Clone, Default, Deserialize, PartialEq, Eq)]
pub struct AppConfig {
    #[serde(default)]
    pub allowlist: AllowlistConfig,
}

impl AppConfig {
    /// Returns the resolved path for the configuration file based on priority:
    /// 1. `/home/{SUDO_USER}/.kiss/config` if `SUDO_USER` env var is present and the file exists.
    /// 2. `$HOME/.kiss/config` if it exists.
    /// 3. `/etc/kiss/config` if it exists.
    /// 4. Fallback path (`/home/{SUDO_USER}/.kiss/config` if `SUDO_USER` is set, else `$HOME/.kiss/config`).
    pub fn get_config_path() -> PathBuf {
        if let Ok(sudo_user) = std::env::var("SUDO_USER") {
            let user = sudo_user.trim();
            if !user.is_empty() {
                let sudo_path = PathBuf::from(format!("/home/{}/.kiss/config", user));
                if sudo_path.exists() {
                    return sudo_path;
                }
            }
        }

        let home = std::env::var("HOME")
            .or_else(|_| std::env::var("USERPROFILE"))
            .unwrap_or_else(|_| ".".into());
        let home_path = PathBuf::from(home).join(".kiss").join("config");
        if home_path.exists() {
            return home_path;
        }

        let etc_path = PathBuf::from("/etc/kiss/config");
        if etc_path.exists() {
            return etc_path;
        }

        if let Ok(sudo_user) = std::env::var("SUDO_USER") {
            let user = sudo_user.trim();
            if !user.is_empty() {
                return PathBuf::from(format!("/home/{}/.kiss/config", user));
            }
        }
        home_path
    }

    /// Loads configuration from resolved config path (`SUDO_USER`, `$HOME`, or `/etc`).
    /// Gracefully falls back to default empty config if missing or unparseable.
    pub fn load() -> Self {
        Self::load_from_path(Self::get_config_path())
    }

    /// Loads configuration from a given path (expanding `~` if needed).
    /// Gracefully falls back to default empty config on read or parse failure.
    pub fn load_from_path<P: AsRef<Path>>(path: P) -> Self {
        let raw_path = path.as_ref();
        let resolved_path = Self::expand_home(raw_path);

        if let Ok(content) = fs::read_to_string(&resolved_path) {
            Self::parse(&content).unwrap_or_default()
        } else {
            Self::default()
        }
    }

    /// Expands `~` prefix to user home directory.
    fn expand_home(path: &Path) -> PathBuf {
        if path.starts_with("~") {
            let home = std::env::var("HOME")
                .or_else(|_| std::env::var("USERPROFILE"))
                .unwrap_or_else(|_| ".".into());
            let mut components = path.components();
            components.next(); // skip '~'
            let mut path_buf = PathBuf::from(home);
            for comp in components {
                path_buf.push(comp);
            }
            path_buf
        } else {
            path.to_path_buf()
        }
    }

    /// Parses TOML content string into `AppConfig`.
    pub fn parse(content: &str) -> Result<Self, toml::de::Error> {
        toml::from_str(content)
    }

    /// Checks if an X11 display identifier (e.g. "X20" or ":20") is allowed.
    pub fn is_display_allowed(&self, display: &str) -> bool {
        self.allowlist.allowed_x11_displays.iter().any(|d| {
            d == display
                || (d.starts_with(':') && display.starts_with('X') && &d[1..] == &display[1..])
                || (d.starts_with('X') && display.starts_with(':') && &d[1..] == &display[1..])
        })
    }

    /// Checks if a virtual input driver name is allowed.
    pub fn is_driver_allowed(&self, driver: &str) -> bool {
        self.allowlist
            .allowed_virtual_drivers
            .iter()
            .any(|d| d == driver)
    }

    /// Checks if a process path or command line is allowed.
    pub fn is_process_allowed(&self, path: &str) -> bool {
        self.allowlist.allowed_processes.iter().any(|p| p == path)
    }

    /// Formats the configuration into a pretty, plain-English summary tree string.
    pub fn display_summary(&self, path: &Path) -> String {
        let format_list = |list: &[String]| -> String {
            if list.is_empty() {
                "None".to_string()
            } else {
                list.join(", ")
            }
        };

        format!(
            "[CONFIG] Configuration loaded from {}\n  ├── Allowed X11 Displays: {}\n  ├── Allowed Virtual Drivers: {}\n  └── Allowed Processes: {}",
            path.display(),
            format_list(&self.allowlist.allowed_x11_displays),
            format_list(&self.allowlist.allowed_virtual_drivers),
            format_list(&self.allowlist.allowed_processes)
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_valid_config() {
        let toml_str = r#"
[allowlist]
allowed_x11_displays = ["X20", "X21"]
allowed_virtual_drivers = ["VirtualPS/2 VMware VMMouse"]
allowed_processes = ["/opt/google/chrome-remote-desktop/chrome-remote-desktop-host"]
"#;
        let config = AppConfig::parse(toml_str).expect("Failed to parse valid config");
        assert_eq!(config.allowlist.allowed_x11_displays, vec!["X20", "X21"]);
        assert_eq!(
            config.allowlist.allowed_virtual_drivers,
            vec!["VirtualPS/2 VMware VMMouse"]
        );
        assert_eq!(
            config.allowlist.allowed_processes,
            vec!["/opt/google/chrome-remote-desktop/chrome-remote-desktop-host"]
        );
    }

    #[test]
    fn test_partial_config_fallback() {
        let toml_str = r#"
[allowlist]
allowed_x11_displays = ["X20"]
"#;
        let config = AppConfig::parse(toml_str).expect("Failed to parse partial config");
        assert_eq!(config.allowlist.allowed_x11_displays, vec!["X20"]);
        assert!(config.allowlist.allowed_virtual_drivers.is_empty());
        assert!(config.allowlist.allowed_processes.is_empty());
    }

    #[test]
    fn test_empty_config_and_invalid_fallback() {
        let empty_config = AppConfig::parse("").unwrap_or_default();
        assert!(empty_config.allowlist.allowed_x11_displays.is_empty());

        let invalid_config = AppConfig::parse("invalid = [[[").unwrap_or_default();
        assert!(invalid_config.allowlist.allowed_x11_displays.is_empty());
    }

    #[test]
    fn test_allowlist_predicates() {
        let toml_str = r#"
[allowlist]
allowed_x11_displays = ["X20", "X21"]
allowed_virtual_drivers = ["VirtualPS/2 VMware VMMouse"]
allowed_processes = ["/opt/google/chrome-remote-desktop/chrome-remote-desktop-host"]
"#;
        let config = AppConfig::parse(toml_str).unwrap();

        assert!(config.is_display_allowed("X20"));
        assert!(config.is_display_allowed("X21"));
        assert!(!config.is_display_allowed("X0"));

        assert!(config.is_driver_allowed("VirtualPS/2 VMware VMMouse"));
        assert!(!config.is_driver_allowed("Random Virtual Driver"));

        assert!(config.is_process_allowed(
            "/opt/google/chrome-remote-desktop/chrome-remote-desktop-host"
        ));
        assert!(!config.is_process_allowed("/usr/bin/malware"));
    }

    #[test]
    fn test_config_path_resolution() {
        let path = AppConfig::get_config_path();
        assert!(!path.as_os_str().is_empty());
    }

    #[test]
    fn test_display_summary() {
        let toml_str = r#"
[allowlist]
allowed_x11_displays = ["X20"]
"#;
        let config = AppConfig::parse(toml_str).unwrap();
        let summary = config.display_summary(Path::new("/tmp/test_config"));
        assert!(summary.contains("[CONFIG] Configuration loaded from /tmp/test_config"));
        assert!(summary.contains("├── Allowed X11 Displays: X20"));
        assert!(summary.contains("├── Allowed Virtual Drivers: None"));
        assert!(summary.contains("└── Allowed Processes: None"));
    }
}
