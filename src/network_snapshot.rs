use anyhow::{Context, Result, bail};
use ipnet::IpNet;
use std::net::IpAddr;
use std::process::Command;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommandSnapshot {
    pub title: String,
    pub command: String,
    pub status: Option<i32>,
    pub stdout: String,
    pub stderr: String,
}

pub fn collect_network_snapshots() -> Vec<CommandSnapshot> {
    [
        (
            "Interfaces",
            "netsh.exe",
            vec!["interface", "show", "interface"],
        ),
        ("IPv4 default routes", "route.exe", vec!["print", "0.0.0.0"]),
        ("IPv6 default routes", "route.exe", vec!["print", "::/0"]),
        (
            "ProxyBridgeRS split routes",
            "powershell.exe",
            vec![
                "-NoProfile",
                "-ExecutionPolicy",
                "Bypass",
                "-Command",
                "Get-NetRoute -InterfaceAlias 'ProxyBridgeRS' | Select-Object -ExpandProperty DestinationPrefix",
            ],
        ),
        (
            "All route ownership",
            "powershell.exe",
            vec![
                "-NoProfile",
                "-ExecutionPolicy",
                "Bypass",
                "-Command",
                "Get-NetRoute | ForEach-Object { \"$($_.DestinationPrefix)|$($_.InterfaceAlias)|$($_.RouteMetric)\" }",
            ],
        ),
    ]
    .into_iter()
    .map(|(title, program, args)| run_snapshot_command(title, program, &args))
    .collect()
}

pub fn run_snapshot_command(title: &str, program: &str, args: &[&str]) -> CommandSnapshot {
    let command = format!("{} {}", program, args.join(" "));
    match run_command(program, args) {
        Ok(snapshot) => CommandSnapshot {
            title: title.to_string(),
            command,
            status: snapshot.status,
            stdout: snapshot.stdout,
            stderr: snapshot.stderr,
        },
        Err(error) => CommandSnapshot {
            title: title.to_string(),
            command,
            status: None,
            stdout: String::new(),
            stderr: format!("{error:#}"),
        },
    }
}

pub fn assert_capture_routes_present(snapshots: &[CommandSnapshot]) -> Result<()> {
    let snapshot = snapshots
        .iter()
        .find(|snapshot| snapshot.title == "ProxyBridgeRS split routes")
        .context("missing ProxyBridgeRS split routes snapshot")?;
    if snapshot.status != Some(0) {
        bail!(
            "ProxyBridgeRS split route snapshot failed with status {:?}: {}",
            snapshot.status,
            snapshot.stderr.trim()
        );
    }

    let routes = parse_destination_prefixes(&snapshot.stdout);
    let required_destinations = [
        "1.1.1.1",
        "128.0.0.1",
        "192.0.2.1",
        "2001:4860::8888",
        "2606:4700::1111",
        "8000::1",
    ];
    let missing = required_destinations
        .into_iter()
        .filter_map(|destination| {
            let ip: IpAddr = destination.parse().ok()?;
            (!routes.iter().any(|route| route.contains(&ip))).then_some(destination)
        })
        .collect::<Vec<_>>();
    if missing.is_empty() {
        return Ok(());
    }

    bail!(
        "ProxyBridgeRS route snapshot is missing capture coverage for {}",
        missing.join(", ")
    );
}

pub fn parse_destination_prefixes(stdout: &str) -> Vec<IpNet> {
    stdout
        .lines()
        .filter_map(|line| line.trim().parse::<IpNet>().ok())
        .collect()
}

pub fn capture_routes_present(snapshots: &[CommandSnapshot]) -> bool {
    assert_capture_routes_present(snapshots).is_ok()
}

/// Reject a more-specific public route owned by another interface. A pair of
/// `/1` routes is otherwise insufficient evidence when a VPN or virtual
/// adapter has a `/24`, `/32`, or similarly specific route for the destination.
pub fn assert_no_competing_capture_routes(snapshots: &[CommandSnapshot]) -> Result<()> {
    let snapshot = snapshots
        .iter()
        .find(|snapshot| snapshot.title == "All route ownership")
        .context("missing all route ownership snapshot")?;
    if snapshot.status != Some(0) {
        bail!(
            "route ownership snapshot failed with status {:?}: {}",
            snapshot.status,
            snapshot.stderr.trim()
        );
    }

    let public_destinations = [
        "1.1.1.1",
        "8.8.8.8",
        "9.9.9.9",
        "2001:4860::8888",
        "2606:4700::1111",
    ];
    let public_destinations = public_destinations
        .into_iter()
        .filter_map(|value| value.parse::<IpAddr>().ok())
        .collect::<Vec<_>>();
    let mut conflicts = Vec::new();

    for line in snapshot.stdout.lines() {
        let mut fields = line.trim().split('|');
        let Some(prefix) = fields.next().and_then(|value| value.parse::<IpNet>().ok()) else {
            continue;
        };
        let interface = fields.next().unwrap_or("unknown").trim();
        if interface.eq_ignore_ascii_case("ProxyBridgeRS") || prefix.prefix_len() <= 1 {
            continue;
        }
        if public_destinations
            .iter()
            .any(|destination| prefix.contains(destination))
        {
            conflicts.push(format!("{} via {}", prefix, interface));
        }
    }

    if conflicts.is_empty() {
        return Ok(());
    }

    bail!(
        "a more-specific public route may bypass ProxyBridgeRS: {}. Disconnect or disable the listed VPN/virtual adapter, then retry",
        conflicts.join(", ")
    );
}

pub fn format_snapshot_section(snapshot: &CommandSnapshot) -> String {
    let status = snapshot
        .status
        .map(|value| value.to_string())
        .unwrap_or_else(|| "not-started".to_string());
    let mut section = format!(
        "== {} ==\ncommand: {}\nstatus={}\n",
        snapshot.title, snapshot.command, status
    );

    if !snapshot.stdout.trim().is_empty() {
        section.push_str("stdout:\n");
        section.push_str(snapshot.stdout.trim());
        section.push('\n');
    }
    if !snapshot.stderr.trim().is_empty() {
        section.push_str("stderr:\n");
        section.push_str(snapshot.stderr.trim());
        section.push('\n');
    }

    section
}

struct RawSnapshot {
    status: Option<i32>,
    stdout: String,
    stderr: String,
}

fn run_command(program: &str, args: &[&str]) -> Result<RawSnapshot> {
    let output = Command::new(program)
        .args(args)
        .output()
        .with_context(|| format!("running {} {}", program, args.join(" ")))?;

    Ok(RawSnapshot {
        status: output.status.code(),
        stdout: String::from_utf8_lossy(&output.stdout).to_string(),
        stderr: String::from_utf8_lossy(&output.stderr).to_string(),
    })
}
