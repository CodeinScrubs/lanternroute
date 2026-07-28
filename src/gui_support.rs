use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct GuiOptions {
    pub socks: String,
    pub dns_via_proxy: bool,
    pub allow_quic: bool,
    pub no_reconnect_apps: bool,
    pub allow_tcp_only: bool,
    pub proxy_local_networks: bool,
    pub bypass_processes: Vec<String>,
    pub bypass_ips: Vec<String>,
    pub bypass_domains: Vec<String>,
    pub bypass_ports: Vec<String>,
    pub rules: Vec<String>,
    pub log_level: String,
    pub smoke_iterations: u8,
}

pub fn profile_path(runtime_home: &Path) -> PathBuf {
    runtime_home.join("gui-settings.json")
}

pub fn load_profile(runtime_home: &Path) -> GuiOptions {
    let path = profile_path(runtime_home);
    let Ok(body) = fs::read_to_string(path) else {
        return GuiOptions::default();
    };
    serde_json::from_str(&body).unwrap_or_default()
}

pub fn save_profile(runtime_home: &Path, options: &GuiOptions) -> std::io::Result<()> {
    fs::create_dir_all(runtime_home)?;
    let body = serde_json::to_string_pretty(options)
        .map_err(|error| std::io::Error::other(format!("serializing GUI profile: {error}")))?;
    let path = profile_path(runtime_home);
    let temporary = path.with_extension("json.tmp");
    fs::write(&temporary, body)?;
    if let Err(rename_error) = fs::rename(&temporary, &path) {
        if path.exists() {
            fs::remove_file(&path)?;
            fs::rename(&temporary, &path)?;
        } else {
            let _ = fs::remove_file(&temporary);
            return Err(rename_error);
        }
    }
    Ok(())
}

impl Default for GuiOptions {
    fn default() -> Self {
        Self {
            socks: "127.0.0.1:10808".to_string(),
            dns_via_proxy: false,
            allow_quic: false,
            no_reconnect_apps: false,
            allow_tcp_only: true,
            proxy_local_networks: false,
            bypass_processes: Vec::new(),
            bypass_ips: Vec::new(),
            bypass_domains: Vec::new(),
            bypass_ports: Vec::new(),
            rules: Vec::new(),
            log_level: "warn".to_string(),
            smoke_iterations: 10,
        }
    }
}

pub fn build_cli_args(command: &str, options: &GuiOptions) -> Vec<String> {
    let mut args = vec![
        command.to_string(),
        "--socks".to_string(),
        options.socks.clone(),
        "--log-level".to_string(),
        options.log_level.clone(),
    ];

    if options.dns_via_proxy {
        args.push("--dns-via-proxy".to_string());
    }
    if options.allow_quic && !options.allow_tcp_only {
        args.push("--allow-quic".to_string());
    }
    if options.no_reconnect_apps {
        args.push("--no-reconnect-apps".to_string());
    }
    if options.proxy_local_networks {
        args.push("--proxy-local-networks".to_string());
    }
    for process in &options.bypass_processes {
        let process = process.trim();
        if !process.is_empty() {
            args.push("--bypass-process".to_string());
            args.push(process.to_string());
        }
    }
    for cidr in &options.bypass_ips {
        let cidr = cidr.trim();
        if !cidr.is_empty() {
            args.push("--bypass-ip".to_string());
            args.push(cidr.to_string());
        }
    }
    for domain in &options.bypass_domains {
        let domain = domain.trim();
        if !domain.is_empty() {
            args.push("--bypass-domain".to_string());
            args.push(domain.to_string());
        }
    }
    for port in &options.bypass_ports {
        let port = port.trim();
        if !port.is_empty() {
            args.push("--bypass-port".to_string());
            args.push(port.to_string());
        }
    }
    for rule in &options.rules {
        let rule = rule.trim();
        if !rule.is_empty() {
            args.push("--rule".to_string());
            args.push(rule.to_string());
        }
    }
    if options.allow_tcp_only && matches!(command, "run" | "smoke-test" | "doctor") {
        args.push("--allow-tcp-only".to_string());
    }
    if command == "smoke-test" {
        args.push("--smoke-iterations".to_string());
        args.push(options.smoke_iterations.max(1).to_string());
    }

    args
}

pub fn build_path_args(command: &str) -> Vec<String> {
    vec![command.to_string()]
}

pub fn cli_exe_for_gui_exe(gui_exe: &Path) -> PathBuf {
    gui_exe.with_file_name("lanternroute.exe")
}

pub fn runtime_home_for_gui_exe(gui_exe: &Path) -> PathBuf {
    let exe_dir = gui_exe.parent().unwrap_or_else(|| Path::new("."));
    if exe_dir.file_name().and_then(|name| name.to_str()) == Some("release")
        && exe_dir
            .parent()
            .and_then(|parent| parent.file_name())
            .and_then(|name| name.to_str())
            == Some("target")
        && let Some(project_root) = exe_dir.parent().and_then(Path::parent)
    {
        return project_root.join(".runtime");
    }

    if let Some(local_app_data) = std::env::var_os("LOCALAPPDATA") {
        return PathBuf::from(local_app_data).join("LanternRoute");
    }

    exe_dir.join(".runtime")
}
