use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use std::fs;
use std::hash::{BuildHasher, Hasher, RandomState};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::time::Duration;

/// Loopback-only sing-box Clash API endpoint used for the live connection
/// table. A fresh random secret is generated for every tunnel session so no
/// other local process can control the engine without reading the runtime
/// state file.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ControlApiEndpoint {
    pub port: u16,
    pub secret: String,
}

pub fn allocate_control_api() -> Result<ControlApiEndpoint> {
    let listener = TcpListener::bind(("127.0.0.1", 0))
        .context("allocating a loopback port for the tunnel control API")?;
    let port = listener
        .local_addr()
        .context("reading the allocated control API port")?
        .port();
    drop(listener);
    Ok(ControlApiEndpoint {
        port,
        secret: generate_secret(),
    })
}

pub fn generate_secret() -> String {
    let mut secret = String::with_capacity(32);
    for _ in 0..2 {
        let value = RandomState::new().build_hasher().finish();
        secret.push_str(&format!("{value:016x}"));
    }
    secret
}

pub fn save_control_api(path: &Path, endpoint: &ControlApiEndpoint) -> Result<()> {
    let parent = path
        .parent()
        .context("control API state path has no parent directory")?;
    fs::create_dir_all(parent).with_context(|| format!("creating {}", parent.display()))?;
    let body = serde_json::to_string_pretty(endpoint).context("serializing control API state")?;
    fs::write(path, body).with_context(|| format!("writing {}", path.display()))
}

pub fn remove_control_api(path: &Path) -> Result<()> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error).with_context(|| format!("removing {}", path.display())),
    }
}

/// Removes per-session control state whenever the owning controller exits,
/// including startup failures and Ctrl+C shutdown.
pub struct ControlApiStateGuard {
    path: Option<PathBuf>,
}

impl ControlApiStateGuard {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self {
            path: Some(path.into()),
        }
    }

    pub fn cleanup(&mut self) -> Result<()> {
        let Some(path) = self.path.take() else {
            return Ok(());
        };
        if let Err(error) = remove_control_api(&path) {
            self.path = Some(path);
            return Err(error);
        }
        Ok(())
    }
}

impl Drop for ControlApiStateGuard {
    fn drop(&mut self) {
        if let Some(path) = &self.path {
            let _ = remove_control_api(path);
        }
    }
}

pub fn load_control_api(path: &Path) -> Result<ControlApiEndpoint> {
    let body = fs::read_to_string(path).with_context(|| {
        format!(
            "reading control API state {}; start a tunnel with `run` first",
            path.display()
        )
    })?;
    serde_json::from_str(&body).with_context(|| format!("parsing {}", path.display()))
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct ConnectionsSnapshot {
    pub download_total: u64,
    pub upload_total: u64,
    pub connections: Option<Vec<ConnectionEntry>>,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct ConnectionEntry {
    pub metadata: ConnectionMetadata,
    pub upload: u64,
    pub download: u64,
    pub chains: Vec<String>,
    pub rule: String,
    pub rule_payload: String,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct ConnectionMetadata {
    pub network: String,
    pub host: String,
    #[serde(rename = "destinationIP")]
    pub destination_ip: String,
    pub destination_port: String,
    pub process_path: String,
}

pub fn fetch_connections(endpoint: &ControlApiEndpoint) -> Result<ConnectionsSnapshot> {
    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .context("building control API client")?;
    let response = client
        .get(format!("http://127.0.0.1:{}/connections", endpoint.port))
        .bearer_auth(&endpoint.secret)
        .send()
        .context("querying the tunnel control API; is a LanternRoute tunnel running?")?;
    if !response.status().is_success() {
        bail!(
            "tunnel control API returned HTTP {}; the state file may be stale - restart the tunnel and retry",
            response.status()
        );
    }
    response
        .json::<ConnectionsSnapshot>()
        .context("parsing the control API connections response")
}

pub fn format_connections_report(snapshot: &ConnectionsSnapshot) -> String {
    let mut connections = snapshot.connections.clone().unwrap_or_default();
    connections.sort_by_key(|entry| std::cmp::Reverse(entry.download + entry.upload));

    let mut report = format!(
        "Active connections: {}  (session totals: up {}, down {})\n",
        connections.len(),
        format_bytes(snapshot.upload_total),
        format_bytes(snapshot.download_total)
    );
    if connections.is_empty() {
        report.push_str("No active connections.\n");
        return report;
    }

    report.push_str(&format!(
        "{:<5} {:<24} {:<36} {:<26} {:<10} {:>10} {:>10}\n",
        "PROTO", "PROCESS", "DESTINATION", "RULE", "OUTBOUND", "UP", "DOWN"
    ));
    for entry in &connections {
        report.push_str(&format!(
            "{:<5} {:<24} {:<36} {:<26} {:<10} {:>10} {:>10}\n",
            truncate(&entry.metadata.network, 5),
            truncate(&process_display(&entry.metadata.process_path), 24),
            truncate(&destination_display(&entry.metadata), 36),
            truncate(&rule_display(entry), 26),
            truncate(&entry.chains.join(">"), 10),
            format_bytes(entry.upload),
            format_bytes(entry.download),
        ));
    }
    report
}

pub fn process_display(process_path: &str) -> String {
    if process_path.is_empty() {
        return "-".to_string();
    }
    Path::new(process_path)
        .file_name()
        .map(|name| name.to_string_lossy().to_string())
        .unwrap_or_else(|| process_path.to_string())
}

fn destination_display(metadata: &ConnectionMetadata) -> String {
    let host = if metadata.host.is_empty() {
        &metadata.destination_ip
    } else {
        &metadata.host
    };
    if metadata.destination_port.is_empty() {
        host.to_string()
    } else {
        format!("{host}:{}", metadata.destination_port)
    }
}

fn rule_display(entry: &ConnectionEntry) -> String {
    if entry.rule_payload.is_empty() {
        entry.rule.clone()
    } else {
        format!("{}({})", entry.rule, entry.rule_payload)
    }
}

pub fn format_bytes(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut value = bytes as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{bytes} B")
    } else {
        format!("{value:.1} {}", UNITS[unit])
    }
}

fn truncate(value: &str, max: usize) -> String {
    if value.chars().count() <= max {
        value.to_string()
    } else {
        let kept: String = value.chars().take(max.saturating_sub(1)).collect();
        format!("{kept}...")
    }
}
