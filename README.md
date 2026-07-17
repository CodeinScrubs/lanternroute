# ProxyBridge RS

**Force every Windows application through your SOCKS5 proxy — no per-app setup, no silent leaks, verified end to end.**

![Platform](https://img.shields.io/badge/platform-Windows%2010%2F11%20x64-0078D6)
![Language](https://img.shields.io/badge/Rust-2024%20edition-orange)
![Engine](https://img.shields.io/badge/data%20plane-sing--box%201.13.14%20TUN-blueviolet)
![License](https://img.shields.io/badge/license-MIT-green)

ProxyBridge RS turns a local SOCKS5 endpoint (v2rayN, Xray, or any client listening on something like `127.0.0.1:10808`) into a **whole-device tunnel**. It captures traffic at the IP routing layer with a Wintun TUN adapter and a pinned [sing-box](https://sing-box.sagernet.org/) engine, so apps that ignore system proxy settings — games, chat apps, CLI tools, services — get proxied too.

The Rust controller owns everything around the data plane: a native GUI and CLI, config generation, engine provisioning with SHA-256 pinning, SOCKS capability probing, route-readiness verification, browser session reconnect, and fail-closed shutdown cleanup.

```text
Windows applications
        |
Windows IP routing table
        |
ProxyBridgeRS TUN adapter (Wintun)
        |
sing-box route rules and DNS handling
        |
SOCKS5 endpoint supplied by v2rayN/Xray
        |
Internet
```

## Why ProxyBridge RS

- **Whole-device capture, not socket hooking.** Routing-level capture covers every process without per-app rules, DLL injection, or a custom packet relay.
- **Fail-closed by design.** If your SOCKS port cannot relay UDP, ProxyBridge RS *blocks* the UDP it cannot proxy instead of silently leaking it around the tunnel. QUIC is blocked by default so browsers fall back to reliably-proxied TCP.
- **It proves itself before and after.** `doctor` probes the real SOCKS5 capabilities (no-auth handshake, TCP CONNECT, UDP ASSOCIATE, and an actual UDP relay round-trip — not just a handshake). The live test starts the tunnel, compares TUN egress against explicit SOCKS egress with latency stats, and verifies route installation. Start and Stop verify that capture routes appear and are fully removed.
- **No routing loops.** Loopback and every common proxy engine (`v2rayN.exe`, `xray.exe`, `sing-box.exe`, clash/mihomo, nekoray, hysteria, and more) are bypassed automatically so the tunnel never captures its own upstream.
- **Keeps your LAN working.** Printers, VMs, WSL, and private networks stay direct by default; capture them intentionally with one switch.
- **Live connection table.** While the tunnel runs, `connections` (CLI) or the GUI **Connections** button shows every active connection — process, destination, matched rule, outbound, and per-connection traffic — plus session totals, powered by a loopback-only engine API secured with a fresh random secret per session.
- **Reconnects your apps for you.** Already-open Chrome, Edge, Firefox, Brave, Opera, Vivaldi, and Telegram TCP sessions are reset after routes are ready, so they rejoin through the tunnel without restarting.
- **Supply-chain pinned.** sing-box `1.13.14` and Wintun `0.14.1` are downloaded on first use from their official sources and verified against pinned SHA-256 hashes (archive *and* extracted binary) before anything runs.
- **Ordered policy rules.** First-match `proxy` / `direct` / `block` rules over process, IP CIDR, domain, port, and transport — with DNS handling and fail-closed UDP guards that user rules cannot accidentally defeat.
- **Portable and small.** Two executables plus PowerShell helpers. No installer, no background service, no kernel driver to sign or trust.

## How it compares

| | ProxyBridge RS | Proxifier | Official ProxyBridge | System proxy |
| --- | --- | --- | --- | --- |
| Capture layer | IP routing (TUN) | Socket-level (proprietary) | WinDivert packet relay | App opt-in |
| Covers apps that ignore proxy settings | Yes | Yes | Yes | No |
| Open source | Yes (MIT) | No | Yes | — |
| UDP honesty | Proven relay or fail-closed block | Depends on config | Depends on relay | Not covered |
| Preflight + live proof diagnostics | Built in | Limited | Limited | — |
| Custom user-mode packet relay to maintain | No — OS + sing-box handle packets | n/a | Yes (state, reinjection, fragmentation) | — |
| Per-process rules | Yes (ordered rules + bypasses) | Yes (mature UI) | Yes | No |
| Live connection table + traffic counters | Yes (GUI + CLI) | Yes | No | — |
| Proxy chains / failover | Not yet | Yes | No | — |

Honest positioning: Proxifier has a more mature Windows lifecycle, connection table, and proxy-chain features; Clash Verge Rev has a broader management ecosystem. ProxyBridge RS's edge is a stronger whole-device route model, verified fail-closed behavior, and a simple open-source deployment. See [ARCHITECTURE.md](ARCHITECTURE.md) for the full comparison, including a future WFP-driver design.

## Quick start

Requirements: Windows 10/11 x64, Administrator rights (TUN routes need them), and a local SOCKS5 endpoint such as v2rayN with its SOCKS listener on `127.0.0.1:10808`.

1. Start v2rayN, keep its local SOCKS port enabled, and turn **off** v2rayN's system proxy mode so ProxyBridge RS owns routing.
2. Grab a release ZIP (or [build from source](#building-from-source)).
3. Launch the GUI:

```powershell
.\target\release\proxybridge-gui.exe
```

The GUI relaunches itself as Administrator when needed. Recommended flow:

- **Doctor** — preflight: SOCKS capabilities, engine provisioning, config validation.
- **Live Test** — an elevated proof run that starts the tunnel temporarily and compares egress IPs and latency.
- **Start / Stop** — daily use. Settings persist to `.runtime\gui-settings.json`; **Guide** explains every field.
- **Connections** — live connection table with traffic counters while the tunnel runs.

The GUI defaults to **TCP-only mode** because many v2rayN SOCKS ports handle TCP correctly but do not relay UDP. Uncheck it only when Doctor reports `SOCKS5 UDP relay: yes`.

### Command line

```powershell
# Preflight report
powershell -ExecutionPolicy Bypass -File .\scripts\Doctor-ProxyBridgeRS.ps1 -Socks 127.0.0.1:10808 -AllowTcpOnly

# Start the tunnel (Ctrl+C stops it and verifies cleanup)
powershell -ExecutionPolicy Bypass -File .\scripts\Start-ProxyBridgeRS.ps1 -Socks 127.0.0.1:10808 -AllowTcpOnly

# Elevated live proof test with latency stats
powershell -ExecutionPolicy Bypass -File .\scripts\Test-LiveProxyBridgeRS.ps1 -Socks 127.0.0.1:10808 -AllowTcpOnly -SmokeIterations 10

# Validate the generated config with the real engine, without starting the tunnel
powershell -ExecutionPolicy Bypass -File .\scripts\Check-ProxyBridgeRS.ps1 -Socks 127.0.0.1:10808

# Stop a stale owned engine (targets only the bundled sing-box path)
powershell -ExecutionPolicy Bypass -File .\scripts\Stop-ProxyBridgeRS.ps1
```

Or call the CLI directly — `run`, `check`, `doctor`, `smoke-test`, `print-config`, `ensure-engine`, `stop`, `connections`, and `reset-browsers`:

```powershell
.\target\release\proxybridge-rs.exe run --socks 127.0.0.1:10808 --allow-tcp-only
```

### Live connection table

While the tunnel runs, show every active connection with its process, destination, matched rule, outbound, and traffic:

```powershell
$env:PROXYBRIDGE_RS_HOME = Join-Path (Get-Location) ".runtime"
.\target\release\proxybridge-rs.exe connections
```

```text
Active connections: 2  (session totals: up 1.2 MiB, down 48.3 MiB)
PROTO PROCESS                  DESTINATION                          RULE                       OUTBOUND           UP       DOWN
tcp   chrome.exe               www.youtube.com:443                  final                      proxy         310 KiB   42.1 MiB
tcp   telegram.exe             149.154.167.51:443                   final                      proxy          88 KiB    5.9 MiB
```

The table is served by a loopback-only engine API protected by a random per-session secret, so no other machine — and no local process without file access to the runtime folder — can query or control the engine.

### Reading the Doctor report

The important lines are:

- `SOCKS listening: yes`
- `SOCKS5 no-auth: yes`
- `SOCKS5 TCP CONNECT: yes`
- `SOCKS5 UDP associate: yes`
- `SOCKS5 UDP relay: yes` — required for true UDP/all-app coverage
- `Mode validation: ok`
- `Wintun: ...\wintun.dll`
- `Owned engine already running: no`
- `Config check: ok`

If `SOCKS5 UDP relay: no`, enable UDP relay on the v2rayN/Xray local SOCKS listener, use a local port that really relays SOCKS5 UDP, or run TCP-only mode for browser-style traffic. There is no local setting that can manufacture upstream UDP support — ProxyBridge RS refuses to pretend otherwise.

## Routing policy

### Defaults

- TUN capture is always used, with full-capture split routes for IPv4 and IPv6 (`0.0.0.0/1`, `128.0.0.0/1`, `::/1`, `8000::/1`).
- QUIC (UDP/443) is blocked so browsers use TCP, which proxies consistently through SOCKS.
- DNS is resolved locally by default; `--dns-via-proxy` switches to DNS-over-HTTPS through the tunnel.
- Private LAN, CGNAT, and unique-local IPv6 ranges stay direct; link-local and multicast always stay direct. `--proxy-local-networks` captures private ranges intentionally.
- TCP-only mode blocks remaining UDP after DNS handling so nothing leaks or stalls; full UDP mode requires a proven SOCKS5 UDP relay.
- MTU defaults to 1500 (`--mtu` accepts 576–9000); engine log level defaults to `warn`.
- Starting a second instance is blocked by a global lock so stale TUN sessions never compete.

### Direct exceptions

Convenience bypasses, added to the built-in loopback and proxy-engine rules:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\Start-ProxyBridgeRS.ps1 `
  -Socks 127.0.0.1:10808 -AllowTcpOnly -BypassProcess game.exe `
  -BypassIp 192.168.50.0/24 -BypassDomain .lan -BypassPort 8000:8100
```

- `--bypass-process` — executable names only (`game.exe`), not paths.
- `--bypass-ip` — valid IPv4/IPv6 CIDR (`192.168.50.0/24`, `fd00::/8`).
- `--bypass-domain` — exact (`example.com`) or suffix (`.example.com`, `*.example.com`).
- `--bypass-port` — a port (`443`) or inclusive range (`8000:8100`).

Invalid values are rejected before the tunnel starts.

### Ordered rules

First-match `proxy` / `direct` / `block` policies, one per line in the GUI or repeated `--rule` arguments:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\Start-ProxyBridgeRS.ps1 `
  -Socks 127.0.0.1:10808 -AllowTcpOnly `
  -Rule "block domain=ads.example.com" `
  -Rule "direct process=game.exe" `
  -Rule "proxy port=443"
```

Matchers: `process=game.exe`, `ip=192.168.50.0/24`, `domain=example.com`, `domain=.example.com` (suffix), `port=443`, `port=8000:8100`, `network=tcp|udp|icmp`. Blank lines and `#` comments are ignored.

Rule precedence is deliberate: DNS hijacking first, then built-in loopback and proxy-engine bypasses, then the QUIC/TCP-only UDP guards, then user rules, then convenience direct exceptions, and finally the proxy default. A user rule can never create a routing loop, capture the local SOCKS engine, or silently defeat the selected fail-closed mode.

### Advanced flags

```powershell
# DNS through the proxy (DNS-over-HTTPS via the tunnel)
... Start-ProxyBridgeRS.ps1 -Socks 127.0.0.1:10808 -DnsViaProxy

# Allow QUIC/HTTP3 UDP (only with a proven UDP relay)
... Start-ProxyBridgeRS.ps1 -Socks 127.0.0.1:10808 -AllowQuic

# Skip resetting already-open browser/chat sessions
... Start-ProxyBridgeRS.ps1 -Socks 127.0.0.1:10808 -NoReconnectApps

# Capture private LAN/VM/WSL destinations through the proxy too
... Start-ProxyBridgeRS.ps1 -Socks 127.0.0.1:10808 -AllowTcpOnly -ProxyLocalNetworks

# More engine logs while diagnosing
... Start-ProxyBridgeRS.ps1 -Socks 127.0.0.1:10808 -LogLevel info

# Manually reset existing browser/chat TCP sessions
$env:PROXYBRIDGE_RS_HOME = Join-Path (Get-Location) ".runtime"
.\target\release\proxybridge-rs.exe reset-browsers
```

## Troubleshooting

**"ProxyBridgeRS already has capture routes before startup"** — a previous session did not clean up. Run `Stop-ProxyBridgeRS.ps1` (or the GUI **Stop**) from an elevated prompt; reboot if routes persist.

**"a more-specific public route may bypass ProxyBridgeRS"** — another VPN or virtual adapter owns routes that would leak around the tunnel. Disconnect or disable it, then retry. This check is intentional: a tunnel that silently loses to another adapter is worse than a refusal to start.

**Browsing breaks with DNS via proxy** — that is why it is off by default. Some upstreams do not carry DNS-over-HTTPS reliably; switch back to local DNS.

**UDP apps fail in TCP-only mode** — expected and intentional. TCP-only mode rejects UDP it cannot proxy rather than leaking it. Get a SOCKS endpoint with working UDP relay for all-app coverage.

**TUN interface creation fails at startup** — usually a missing/blocked Wintun driver load. Run `ensure-engine` or Doctor again and retry from an elevated prompt; the error output includes a specific hint when this happens.

Engine logs from helper-script runs live under `.runtime\runtime\logs`.

## Coverage limits (read this before relying on it)

No SOCKS-based design can transparently forward every possible Windows packet. ICMP, broadcast/multicast discovery, and UDP applications need upstream support or a different transport. SOCKS remains the upstream constraint: TCP is the reliable path, and UDP depends entirely on whether your local SOCKS listener really relays UDP — which Doctor measures directly instead of assuming.

Validate your exact Windows build, SOCKS profile, and applications with `Doctor` and the live test before unattended use. See [ARCHITECTURE.md](ARCHITECTURE.md) for the mode matrix, exception syntax, and the comparison with Proxifier, WinDivert-based ProxyBridge, and a future WFP redirect design.

## Building from source

```powershell
# Optimized binaries (LTO, stripped) into target\release
powershell -ExecutionPolicy Bypass -File .\scripts\Build-Release.ps1

# Release ZIP + SHA-256 checksum
powershell -ExecutionPolicy Bypass -File .\scripts\Package-Release.ps1 -Version 0.1.0
```

The portable package keeps the documented layout: executables under `target\release`, helper scripts under `scripts`. sing-box and Wintun are **not** redistributed in the repo or ZIP — they are downloaded on first use and hash-verified (see [THIRD_PARTY.md](THIRD_PARTY.md)).

## Runtime files

Helper scripts set `PROXYBRIDGE_RS_HOME` to `.runtime` inside the project so Start, Stop, Doctor, and the live test share one runtime home. Without the variable, the app uses `%LOCALAPPDATA%\ProxyBridgeRS`. Generated sing-box config is validated with `sing-box check` before every start.

## Project documentation

- [ARCHITECTURE.md](ARCHITECTURE.md) — data path, modes, rule precedence, comparisons, roadmap
- [CHANGELOG.md](CHANGELOG.md) — release history
- [CONTRIBUTING.md](CONTRIBUTING.md) — local verification workflow
- [SECURITY.md](SECURITY.md) — vulnerability reporting
- [RELEASE_CHECKLIST.md](RELEASE_CHECKLIST.md) — what a release must prove
- [THIRD_PARTY.md](THIRD_PARTY.md) — pinned upstream components

## License

MIT — see [LICENSE](LICENSE).
