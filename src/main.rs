use anyhow::{Context, Result, bail};
use clap::{ArgAction, Args, Parser, Subcommand};
use proxybridge_rs::admin::is_elevated;
use proxybridge_rs::browser_reset::reset_browser_connections_with_context;
use proxybridge_rs::config::{DnsMode, RuntimeOptions, build_sing_box_config};
use proxybridge_rs::endpoint::SocksEndpoint;
use proxybridge_rs::engine::{
    EnginePaths, ProcessJob, acquire_engine_lock, check_sing_box_config, ensure_sing_box_ready,
    find_running_owned_engines, format_stop_summary, sing_box_version, start_sing_box_foreground,
    start_sing_box_quiet_with_logs, stop_owned_engines, stop_sing_box_child,
    tun_start_failure_hint, write_runtime_config,
};
use proxybridge_rs::network_snapshot::{
    CommandSnapshot, assert_capture_routes_present, assert_no_competing_capture_routes,
    capture_routes_present, collect_network_snapshots, format_snapshot_section,
    proxybridge_interface_present,
};
use proxybridge_rs::rules::{normalize_domain, normalize_process_name, parse_rule_lines};
use proxybridge_rs::smoke::{
    assert_dns_https_ok, assert_same_egress_ip, combine_smoke_and_cleanup_results,
    summarize_latency,
};
use proxybridge_rs::socks_probe::{probe_socks5, probe_socks5_tcp, validate_socks_for_mode};
use std::path::PathBuf;
use std::sync::mpsc;
use std::time::Duration;

#[derive(Parser, Debug)]
#[command(name = "proxybridge-rs")]
#[command(about = "Windows TUN-to-SOCKS whole-device proxy controller")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Start the TUN tunnel in the foreground until Ctrl+C.
    Run(RunArgs),
    /// Generate and validate the sing-box config without starting the tunnel.
    Check(RunArgs),
    /// Run preflight, engine provisioning, and config validation diagnostics.
    Doctor(RunArgs),
    /// Start the tunnel temporarily and prove curl traffic goes through SOCKS.
    SmokeTest(RunArgs),
    /// Print the generated sing-box config.
    PrintConfig(RunArgs),
    /// Download/provision the bundled TUN engine.
    EnsureEngine(PathArgs),
    /// Stop an already-running owned bundled sing-box engine.
    Stop(PathArgs),
    /// Reset existing Chrome/Firefox/Telegram TCP sessions so they reconnect through TUN.
    ResetBrowsers,
}

#[derive(Args, Clone, Debug)]
struct RunArgs {
    /// Local SOCKS5 endpoint exposed by v2rayN/xray.
    #[arg(long, default_value = "127.0.0.1:10808")]
    socks: SocksEndpoint,

    /// Resolve DNS through the proxy. Off by default because it can break browsing on some setups.
    #[arg(long, default_value_t = false)]
    dns_via_proxy: bool,

    /// Allow QUIC/HTTP3 UDP instead of forcing browsers back to TCP.
    #[arg(long, default_value_t = false)]
    allow_quic: bool,

    /// Do not reset already-open browser/chat app TCP sessions after startup.
    #[arg(long, default_value_t = false)]
    no_reconnect_apps: bool,

    /// Capture private/LAN/CGNAT/ULA destinations through the proxy instead of
    /// preserving direct local-network access. Link-local and multicast remain direct.
    #[arg(long, default_value_t = false)]
    proxy_local_networks: bool,

    /// Permit TCP-only mode when upstream SOCKS refuses UDP. This does not satisfy all-app coverage.
    #[arg(long, default_value_t = false)]
    allow_tcp_only: bool,

    /// sing-box engine directory. Defaults to %LOCALAPPDATA%\ProxyBridgeRS\engine.
    #[arg(long)]
    engine_dir: Option<PathBuf>,

    /// Generated sing-box config path.
    #[arg(long)]
    config_path: Option<PathBuf>,

    /// TUN MTU.
    #[arg(long, default_value_t = 1500)]
    mtu: u16,

    /// sing-box log level: trace, debug, info, warn, or error.
    #[arg(long, default_value = "warn")]
    log_level: String,

    /// Add a process executable name to the direct/bypass list. Repeatable.
    #[arg(long = "bypass-process", value_name = "EXE", action = ArgAction::Append)]
    bypass_processes: Vec<String>,

    /// Add an IP network in CIDR notation to the direct/bypass list. Repeatable.
    #[arg(long = "bypass-ip", value_name = "CIDR", action = ArgAction::Append)]
    bypass_ips: Vec<String>,

    /// Add a domain or leading-dot domain suffix to the direct/bypass list. Repeatable.
    #[arg(long = "bypass-domain", value_name = "DOMAIN", action = ArgAction::Append)]
    bypass_domains: Vec<String>,

    /// Add a destination port or range such as 443 or 8000:8100. Repeatable.
    #[arg(long = "bypass-port", value_name = "PORT|START:END", action = ArgAction::Append)]
    bypass_ports: Vec<String>,

    /// Add an ordered rule: "direct process=game.exe", "block domain=ads.example", etc.
    #[arg(long = "rule", value_name = "ACTION MATCHER=VALUE", action = ArgAction::Append)]
    rules: Vec<String>,

    /// Number of repeated curl samples for smoke-test latency/stability proof.
    #[arg(long, default_value_t = 3)]
    smoke_iterations: u8,
}

#[derive(Args, Clone, Debug)]
struct PathArgs {
    /// sing-box engine directory. Defaults to %LOCALAPPDATA%\ProxyBridgeRS\engine.
    #[arg(long)]
    engine_dir: Option<PathBuf>,

    /// Generated sing-box config path.
    #[arg(long)]
    config_path: Option<PathBuf>,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Commands::Run(args) => run(args),
        Commands::Check(args) => check(args),
        Commands::Doctor(args) => doctor(args),
        Commands::SmokeTest(args) => smoke_test(args),
        Commands::PrintConfig(args) => print_config(args),
        Commands::EnsureEngine(args) => {
            let paths = EnginePaths::new(args.engine_dir, args.config_path)?;
            let exe = ensure_sing_box_ready(&paths)?;
            println!("{}", exe.display());
            Ok(())
        }
        Commands::Stop(args) => stop(args),
        Commands::ResetBrowsers => {
            let summary = reset_browser_connections_with_context()?;
            println!("inspected={} reset={}", summary.inspected, summary.reset);
            Ok(())
        }
    }
}

fn stop(args: PathArgs) -> Result<()> {
    if !is_elevated() {
        bail!(
            "Stopping a TUN session needs Administrator. Re-open PowerShell or the GUI as Administrator."
        );
    }
    let paths = EnginePaths::new(args.engine_dir, args.config_path)?;
    let exe = paths.sing_box_exe();
    let (running, stopped_pids) = stop_owned_engines(&exe)?;
    wait_for_capture_cleanup()?;
    println!("{}", format_stop_summary(&running, &stopped_pids));
    Ok(())
}

fn run(args: RunArgs) -> Result<()> {
    if !is_elevated() {
        bail!(
            "TUN mode needs Administrator. Re-open PowerShell or Windows Terminal as Administrator."
        );
    }
    let _engine_lock = acquire_engine_lock()?;

    let socks_probe = probe_for_mode(
        &args.socks,
        Duration::from_millis(1000),
        args.allow_tcp_only,
    );
    validate_socks_for_mode(&args.socks, &socks_probe, args.allow_tcp_only)?;
    if args.allow_tcp_only && !socks_probe.usable_for_udp() {
        eprintln!(
            "Warning: TCP-only mode selected; UDP-heavy apps will not satisfy all-app coverage."
        );
    }

    let options = options_from_args(&args)?;
    let paths = EnginePaths::new(args.engine_dir, args.config_path)?;
    let exe = ensure_sing_box_ready(&paths)?;
    write_runtime_config(&paths, &options)?;
    check_sing_box_config(&exe, &paths.config_path)?;
    ensure_capture_routes_absent()?;

    println!("ProxyBridge RS starting TUN -> SOCKS {}", options.socks);
    println!("Config: {}", paths.config_path.display());
    println!("Engine: {}", exe.display());
    println!("Wintun: {}", paths.wintun_dll().display());
    println!("Press Ctrl+C to stop.");

    let (tx, rx) = mpsc::channel();
    ctrlc::set_handler(move || {
        let _ = tx.send(());
    })
    .context("installing Ctrl+C handler")?;

    println!("Waiting for ProxyBridgeRS TUN routes...");
    let (mut child, _job) = start_foreground_with_ready_routes(&exe, &paths.config_path)?;
    println!("ProxyBridgeRS TUN routes are ready; traffic capture is active.");

    if options.reconnect_apps {
        match reset_browser_connections_with_context() {
            Ok(summary) => eprintln!(
                "Reconnected existing browser sessions after TUN readiness: inspected={} reset={}",
                summary.inspected, summary.reset
            ),
            Err(error) => eprintln!("Browser reconnect cleanup failed: {error:#}"),
        }
    }

    let status = loop {
        if let Some(status) = child.try_wait().context("checking sing-box status")? {
            break status;
        }
        if rx.try_recv().is_ok() {
            let deadline = std::time::Instant::now() + Duration::from_secs(5);
            let mut exited_status = None;
            while std::time::Instant::now() < deadline {
                if let Some(status) = child.try_wait().context("waiting for sing-box to stop")? {
                    exited_status = Some(status);
                    break;
                }
                std::thread::sleep(Duration::from_millis(100));
            }
            if let Some(status) = exited_status {
                break status;
            }
            if child
                .try_wait()
                .context("checking sing-box shutdown")?
                .is_none()
            {
                child.kill().context("stopping sing-box")?;
            }
            break child.wait().context("waiting for sing-box to stop")?;
        }
        std::thread::sleep(Duration::from_millis(200));
    };
    if status.success() {
        Ok(())
    } else {
        bail!("sing-box exited with {status}");
    }
}

fn check(args: RunArgs) -> Result<()> {
    let options = options_from_args(&args)?;
    let paths = EnginePaths::new(args.engine_dir, args.config_path)?;
    let exe = ensure_sing_box_ready(&paths)?;
    write_runtime_config(&paths, &options)?;
    check_sing_box_config(&exe, &paths.config_path)?;
    println!("OK: {}", paths.config_path.display());
    Ok(())
}

fn doctor(args: RunArgs) -> Result<()> {
    let options = options_from_args(&args)?;
    let paths = EnginePaths::new(args.engine_dir, args.config_path)?;

    println!("ProxyBridge RS doctor");
    println!("Admin: {}", yes_no(is_elevated()));
    println!("SOCKS: {}", options.socks);
    let socks_probe = probe_socks5(&options.socks, Duration::from_millis(1000));
    println!("SOCKS listening: {}", yes_no(socks_probe.tcp_port_open));
    println!("SOCKS5 no-auth: {}", yes_no(socks_probe.socks5_no_auth));
    if let Some(error) = &socks_probe.socks5_no_auth_error {
        println!("SOCKS5 no-auth error: {error}");
    }
    println!("SOCKS5 TCP CONNECT: {}", yes_no(socks_probe.tcp_connect));
    if let Some(error) = &socks_probe.tcp_connect_error {
        println!("SOCKS5 TCP CONNECT error: {error}");
    }
    println!(
        "SOCKS5 UDP associate: {}",
        yes_no(socks_probe.udp_associate)
    );
    if let Some(addr) = socks_probe.udp_bind_addr {
        println!("SOCKS5 UDP bind: {addr}");
    }
    if let Some(error) = &socks_probe.udp_associate_error {
        println!("SOCKS5 UDP associate error: {error}");
    }
    println!("SOCKS5 UDP relay: {}", yes_no(socks_probe.udp_relay));
    if let Some(error) = &socks_probe.udp_relay_error {
        println!("SOCKS5 UDP relay error: {error}");
    }
    println!(
        "DNS via proxy: {}",
        yes_no(matches!(options.dns_mode, DnsMode::RemoteViaProxy))
    );
    println!("QUIC blocked: {}", yes_no(options.block_quic));
    println!("Reconnect apps: {}", yes_no(options.reconnect_apps));
    println!(
        "Proxy local networks: {}",
        yes_no(options.proxy_local_networks)
    );
    println!("TCP-only allowed: {}", yes_no(args.allow_tcp_only));
    println!("Bypass loopback: 127.0.0.0/8, ::1/128, ::ffff:127.0.0.0/104");
    println!(
        "Bypass proxy engines: xray.exe, v2ray.exe, v2rayN.exe, sing-box.exe, proxybridge-rs.exe"
    );
    println!("Log level: {}", options.log_level);
    let mode_error =
        match validate_socks_for_mode(&options.socks, &socks_probe, args.allow_tcp_only) {
            Ok(()) => {
                println!("Mode validation: ok");
                None
            }
            Err(error) => {
                println!("Mode validation: failed: {error}");
                Some(error)
            }
        };

    let exe = ensure_sing_box_ready(&paths)?;
    println!("Engine: {}", exe.display());
    println!("Engine version: {}", sing_box_version(&exe)?);
    println!("Wintun: {}", paths.wintun_dll().display());
    let running = find_running_owned_engines(&exe);
    println!(
        "Owned engine already running: {}",
        yes_no(!running.is_empty())
    );
    for engine in running {
        println!(
            "Owned engine process: pid={} path={}",
            engine.pid,
            engine.exe_path.display()
        );
    }

    write_runtime_config(&paths, &options)?;
    check_sing_box_config(&exe, &paths.config_path)?;
    println!("Config check: ok");
    println!("Config: {}", paths.config_path.display());

    mode_error.map_or(Ok(()), Err)
}

fn smoke_test(args: RunArgs) -> Result<()> {
    if !is_elevated() {
        bail!("Smoke test needs Administrator because it temporarily starts TUN routing.");
    }
    let _engine_lock = acquire_engine_lock()?;

    let options = options_from_args(&args)?;
    let socks_probe = probe_for_mode(
        &options.socks,
        Duration::from_millis(1000),
        args.allow_tcp_only,
    );
    validate_socks_for_mode(&options.socks, &socks_probe, args.allow_tcp_only)?;

    let paths = EnginePaths::new(args.engine_dir, args.config_path)?;
    let exe = ensure_sing_box_ready(&paths)?;
    write_runtime_config(&paths, &options)?;
    check_sing_box_config(&exe, &paths.config_path)?;
    ensure_capture_routes_absent()?;

    println!("Starting temporary TUN session...");
    let log_dir = paths.log_dir();
    let (mut child, _job, snapshots) =
        start_temporary_tun_with_ready_routes(&exe, &paths.config_path, &paths, &log_dir)?;
    println!("Temporary engine logs: {}", log_dir.display());
    println!("Network snapshot after temporary TUN start:");
    for snapshot in &snapshots {
        println!("{}", format_snapshot_section(snapshot));
    }
    let capture_result = assert_capture_routes_present(&snapshots);
    if capture_result.is_err() {
        let cleanup_result = stop_sing_box_child(&mut child);
        return combine_smoke_and_cleanup_results(capture_result, cleanup_result);
    }

    let result = run_smoke_checks(&options, args.smoke_iterations);
    let stop_result = stop_sing_box_child(&mut child);
    combine_smoke_and_cleanup_results(result, stop_result)
}

fn wait_for_tun_ready(
    child: &mut std::process::Child,
    paths: &EnginePaths,
    log_dir: &std::path::Path,
    timeout: Duration,
    interval: Duration,
) -> Result<Vec<CommandSnapshot>> {
    let deadline = std::time::Instant::now() + timeout;

    loop {
        if let Some(status) = child
            .try_wait()
            .context("checking temporary sing-box status")?
        {
            let stderr_path = log_dir.join("sing-box.stderr.log");
            let stderr = std::fs::read_to_string(&stderr_path).unwrap_or_default();
            if let Some(hint) = tun_start_failure_hint(&stderr, &paths.wintun_dll()) {
                bail!("sing-box exited before smoke checks with {status}\n{hint}");
            }
            bail!("sing-box exited before smoke checks with {status}");
        }

        let last_snapshots = collect_network_snapshots();
        if capture_routes_present(&last_snapshots) {
            assert_no_competing_capture_routes(&last_snapshots)
                .context("checking route ownership after TUN startup")?;
            return Ok(last_snapshots);
        }

        if std::time::Instant::now() >= deadline {
            assert_capture_routes_present(&last_snapshots)
                .context("timed out waiting for ProxyBridgeRS split routes")?;
        }

        std::thread::sleep(interval);
    }
}

fn wait_for_capture_routes_with_child(
    child: &mut std::process::Child,
    timeout: Duration,
    interval: Duration,
) -> Result<Vec<CommandSnapshot>> {
    let deadline = std::time::Instant::now() + timeout;

    loop {
        if let Some(status) = child
            .try_wait()
            .context("checking sing-box startup status")?
        {
            bail!("sing-box exited before TUN routes became ready with {status}");
        }

        let last_snapshots = collect_network_snapshots();
        if capture_routes_present(&last_snapshots) {
            assert_no_competing_capture_routes(&last_snapshots)
                .context("checking route ownership after TUN startup")?;
            return Ok(last_snapshots);
        }

        if std::time::Instant::now() >= deadline {
            assert_capture_routes_present(&last_snapshots)
                .context("timed out waiting for ProxyBridgeRS split routes")?;
        }

        std::thread::sleep(interval);
    }
}

fn start_foreground_with_ready_routes(
    exe: &std::path::Path,
    config_path: &std::path::Path,
) -> Result<(std::process::Child, ProcessJob)> {
    let mut last_error = None;
    for attempt in 1..=3 {
        let (mut child, job) = start_sing_box_foreground(exe, config_path)?;
        match wait_for_capture_routes_with_child(
            &mut child,
            Duration::from_secs(15),
            Duration::from_secs(1),
        ) {
            Ok(_) => return Ok((child, job)),
            Err(error) => {
                let _ = stop_sing_box_child(&mut child);
                last_error = Some(error);
                if attempt < 3 {
                    std::thread::sleep(Duration::from_secs(2));
                }
            }
        }
    }

    Err(last_error
        .unwrap_or_else(|| anyhow::anyhow!("TUN startup failed without a diagnostic"))
        .context("TUN startup failed after 3 attempts"))
}

fn start_temporary_tun_with_ready_routes(
    exe: &std::path::Path,
    config_path: &std::path::Path,
    paths: &EnginePaths,
    log_dir: &std::path::Path,
) -> Result<(std::process::Child, ProcessJob, Vec<CommandSnapshot>)> {
    let mut last_error = None;
    for attempt in 1..=3 {
        let (mut child, job) = start_sing_box_quiet_with_logs(exe, config_path, log_dir)?;
        match wait_for_tun_ready(
            &mut child,
            paths,
            log_dir,
            Duration::from_secs(20),
            Duration::from_secs(1),
        ) {
            Ok(snapshots) => return Ok((child, job, snapshots)),
            Err(error) => {
                let _ = stop_sing_box_child(&mut child);
                last_error = Some(error);
                if attempt < 3 {
                    std::thread::sleep(Duration::from_secs(2));
                }
            }
        }
    }

    Err(last_error
        .unwrap_or_else(|| anyhow::anyhow!("TUN startup failed without a diagnostic"))
        .context("temporary TUN startup failed after 3 attempts"))
}

fn ensure_capture_routes_absent() -> Result<()> {
    let snapshots = collect_network_snapshots();
    assert_no_competing_capture_routes(&snapshots)
        .context("checking for competing VPN/virtual-adapter routes before startup")?;
    if capture_routes_present(&snapshots) {
        bail!(
            "ProxyBridgeRS already has capture routes before startup; stop the stale tunnel or reboot Windows before retrying"
        );
    }
    Ok(())
}

fn wait_for_capture_cleanup() -> Result<()> {
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    loop {
        let snapshots = collect_network_snapshots();
        if !capture_routes_present(&snapshots) && !proxybridge_interface_present(&snapshots) {
            return Ok(());
        }
        if std::time::Instant::now() >= deadline {
            bail!(
                "ProxyBridgeRS cleanup is incomplete: capture routes or the ProxyBridgeRS interface remain. Re-run Stop after a few seconds or reboot Windows before starting again"
            );
        }
        std::thread::sleep(Duration::from_millis(250));
    }
}

fn run_smoke_checks(options: &RuntimeOptions, smoke_iterations: u8) -> Result<()> {
    if options.reconnect_apps {
        match reset_browser_connections_with_context() {
            Ok(summary) => println!(
                "Reconnect cleanup: inspected={} reset={}",
                summary.inspected, summary.reset
            ),
            Err(error) => println!("Reconnect cleanup warning: {error:#}"),
        }
    }

    let iterations = smoke_iterations.max(1);
    let mut explicit_latencies = Vec::with_capacity(iterations as usize);
    let mut tun_latencies = Vec::with_capacity(iterations as usize);
    for sample in 1..=iterations {
        let explicit = curl_text(
            &format!("explicit SOCKS egress sample {sample}/{iterations}"),
            &[
                "--socks5-hostname",
                &options.socks.to_string(),
                "https://api.ipify.org",
            ],
        )?;
        let tunneled = curl_text(
            &format!("TUN egress sample {sample}/{iterations}"),
            &["--noproxy", "*", "https://api.ipify.org"],
        )?;

        println!("Explicit SOCKS egress IP: {}", explicit.body);
        println!("TUN egress IP: {}", tunneled.body);
        assert_same_egress_ip(&explicit.body, &tunneled.body)?;
        explicit_latencies.push(explicit.elapsed_ms);
        tun_latencies.push(tunneled.elapsed_ms);
    }

    let explicit_summary = summarize_latency(&explicit_latencies)?;
    let tun_summary = summarize_latency(&tun_latencies)?;
    println!(
        "Explicit SOCKS latency: samples={} avg={} ms max={} ms",
        explicit_summary.count, explicit_summary.average_ms, explicit_summary.max_ms
    );
    println!(
        "TUN latency: samples={} avg={} ms max={} ms",
        tun_summary.count, tun_summary.average_ms, tun_summary.max_ms
    );
    println!(
        "Latency delta avg: TUN {} ms vs explicit SOCKS {} ms",
        tun_summary.average_ms, explicit_summary.average_ms
    );

    let dns_page = curl_text("TUN DNS/HTTPS", &["--noproxy", "*", "https://example.com"])?;
    assert_dns_https_ok(&dns_page.body)?;
    println!("DNS/HTTPS smoke check: ok");

    Ok(())
}

struct CurlResult {
    body: String,
    elapsed_ms: u128,
}

fn curl_text(label: &str, args: &[&str]) -> Result<CurlResult> {
    let mut command_args = vec![
        "--silent",
        "--show-error",
        "--location",
        "--max-time",
        "20",
        "--connect-timeout",
        "10",
    ];
    command_args.extend_from_slice(args);

    let started = std::time::Instant::now();
    let mut last_output = None;
    for attempt in 1..=3 {
        let output = std::process::Command::new("curl.exe")
            .args(&command_args)
            .output()
            .context("running curl.exe")?;
        if output.status.success() {
            let elapsed = started.elapsed();
            let body = String::from_utf8_lossy(&output.stdout).trim().to_string();
            println!("{label}: curl completed in {} ms", elapsed.as_millis());
            return Ok(CurlResult {
                body,
                elapsed_ms: elapsed.as_millis(),
            });
        }

        last_output = Some(output);
        if attempt < 3 {
            std::thread::sleep(Duration::from_millis(300 * attempt));
        }
    }

    let elapsed = started.elapsed();
    let output = last_output.expect("curl retry loop produced no output");
    bail!(
        "curl.exe failed after {:?} (3 attempts)\nargs: {:?}\nstdout:\n{}\nstderr:\n{}",
        elapsed,
        command_args,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

fn yes_no(value: bool) -> &'static str {
    if value { "yes" } else { "no" }
}

fn probe_for_mode(
    endpoint: &SocksEndpoint,
    timeout: Duration,
    allow_tcp_only: bool,
) -> proxybridge_rs::socks_probe::SocksProbeResult {
    if allow_tcp_only {
        probe_socks5_tcp(endpoint, timeout)
    } else {
        probe_socks5(endpoint, timeout)
    }
}

fn print_config(args: RunArgs) -> Result<()> {
    let options = options_from_args(&args)?;
    let config = build_sing_box_config(&options);
    let body = serde_json::to_string_pretty(&config).context("serializing config")?;
    println!("{body}");
    Ok(())
}

fn options_from_args(args: &RunArgs) -> Result<RuntimeOptions> {
    if args.allow_tcp_only && args.allow_quic {
        bail!(
            "--allow-quic cannot be combined with --allow-tcp-only because TCP-only mode blocks UDP"
        );
    }
    if !(576..=9000).contains(&args.mtu) {
        bail!("--mtu must be between 576 and 9000 bytes");
    }

    let direct_process_names = RuntimeOptions::default().direct_process_names;
    let mut custom_direct_process_names = Vec::new();
    for process in &args.bypass_processes {
        let process = normalize_process_name(process).with_context(
            || "--bypass-process must be a non-empty executable name without a path",
        )?;
        if !direct_process_names
            .iter()
            .any(|existing| existing.eq_ignore_ascii_case(&process))
            && !custom_direct_process_names
                .iter()
                .any(|existing: &String| existing.eq_ignore_ascii_case(&process))
        {
            custom_direct_process_names.push(process.to_string());
        }
    }

    let mut direct_ip_cidrs = Vec::new();
    for cidr in &args.bypass_ips {
        let cidr = cidr.trim();
        let network = cidr
            .parse::<ipnet::IpNet>()
            .with_context(|| format!("invalid --bypass-ip CIDR: {cidr:?}"))?;
        let normalized = network.to_string();
        if !direct_ip_cidrs
            .iter()
            .any(|existing| existing == &normalized)
        {
            direct_ip_cidrs.push(normalized);
        }
    }

    let mut direct_domains = Vec::new();
    let mut direct_domain_suffixes = Vec::new();
    for domain in &args.bypass_domains {
        let normalized = normalize_domain(domain).with_context(|| {
            "--bypass-domain must be a domain such as example.com or a suffix such as .example.com"
        })?;
        if normalized.starts_with('.') {
            if !direct_domain_suffixes.contains(&normalized) {
                direct_domain_suffixes.push(normalized);
            }
        } else if !direct_domains.contains(&normalized) {
            direct_domains.push(normalized);
        }
    }

    let mut direct_ports = Vec::new();
    let mut direct_port_ranges = Vec::new();
    for value in &args.bypass_ports {
        let value = value.trim();
        if let Ok(port) = value.parse::<u16>() {
            if port == 0 {
                bail!("--bypass-port must be between 1 and 65535");
            }
            if !direct_ports.contains(&port) {
                direct_ports.push(port);
            }
            continue;
        }

        let Some((start, end)) = value.split_once(':') else {
            bail!("--bypass-port must be a port such as 443 or a range such as 8000:8100");
        };
        let start = if start.is_empty() {
            None
        } else {
            Some(
                start
                    .parse::<u16>()
                    .with_context(|| format!("invalid --bypass-port range start: {start:?}"))?,
            )
        };
        let end = if end.is_empty() {
            None
        } else {
            Some(
                end.parse::<u16>()
                    .with_context(|| format!("invalid --bypass-port range end: {end:?}"))?,
            )
        };
        if start.is_none() && end.is_none()
            || start == Some(0)
            || end == Some(0)
            || matches!((start, end), (Some(first), Some(last)) if first > last)
        {
            bail!("invalid --bypass-port range {value:?}");
        }
        if !direct_port_ranges.iter().any(|existing| existing == value) {
            direct_port_ranges.push(value.to_string());
        }
    }

    let user_rules = parse_rule_lines(&args.rules)?;

    Ok(RuntimeOptions {
        socks: args.socks.clone(),
        dns_mode: if args.dns_via_proxy {
            DnsMode::RemoteViaProxy
        } else {
            DnsMode::Local
        },
        block_quic: !args.allow_quic,
        tcp_only: args.allow_tcp_only,
        reconnect_apps: !args.no_reconnect_apps,
        proxy_local_networks: args.proxy_local_networks,
        mtu: args.mtu,
        log_level: args.log_level.clone(),
        direct_process_names,
        custom_direct_process_names,
        direct_ip_cidrs,
        direct_domains,
        direct_domain_suffixes,
        direct_ports,
        direct_port_ranges,
        user_rules,
        ..RuntimeOptions::default()
    })
}
