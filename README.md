# ProxyBridge RS

ProxyBridge RS is a Windows-only Rust control app for forcing the whole computer through a local SOCKS5 proxy such as v2rayN at `127.0.0.1:10808`.

The Rust app owns the UX, config generation, engine provisioning, validation, lifecycle checks, and browser reconnect cleanup. The packet data plane is sing-box TUN, because that is the reliable low-latency path on Windows and avoids the fragile WinDivert relay behavior we saw in the old app.

## Goal

Start v2rayN, keep its local SOCKS port enabled, turn off v2rayN's system proxy mode, then run ProxyBridge RS as Administrator:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\Start-ProxyBridgeRS.ps1 -Socks 127.0.0.1:10808 -AllowTcpOnly
```

ProxyBridge RS should then route laptop traffic through that SOCKS port while bypassing the local proxy engine processes (`v2rayN.exe`, `xray.exe`, `sing-box.exe`, and this app) so the tunnel does not capture itself.

This is a release candidate, not a promise that every Windows packet or every
upstream proxy can carry every protocol. Validate your exact Windows build,
SOCKS profile, and applications with `Doctor` and the live test before relying
on it for unattended use.

Read [ARCHITECTURE.md](ARCHITECTURE.md) for the data path, mode choices,
exception syntax, and a comparison with Proxifier, WinDivert-based ProxyBridge,
and a future WFP redirect design.

## Commands

Build the optimized binary:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\Build-Release.ps1
```

Create a release ZIP and checksum after building:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\Package-Release.ps1 -Version 0.1.0
```

The portable package preserves the documented project layout: executables are
under `target\release` and helper scripts are under `scripts`. sing-box and
Wintun are downloaded on first use and verified by pinned SHA-256 hashes; they
are not checked into GitHub.

Launch the native Windows GUI:

```powershell
.\target\release\proxybridge-gui.exe
```

The GUI relaunches as Administrator when needed, uses the same `.runtime` folder as the helper scripts, and controls the same `proxybridge-rs.exe` command path. Use `Doctor` for preflight, `Live Test` for an elevated proof run, and `Start` / `Stop` for daily use. The GUI defaults to `TCP-only` checked because many v2rayN SOCKS ports handle TCP correctly but do not relay UDP; uncheck it only when Doctor reports `SOCKS5 UDP relay: yes`.
The GUI also accepts optional comma-separated direct exceptions for apps,
CIDRs, domains, and ports. These are routed directly and are added to the
built-in loopback and proxy-engine bypasses. Leave them empty unless a
specific application, private network, hostname, or service needs direct
access.
Private LAN, CGNAT, and unique-local IPv6 ranges stay direct by default so
printers, VMs, WSL, and local services keep working. Enable `Proxy local
networks` in the GUI, or pass `-ProxyLocalNetworks` to a helper script, only
when those destinations must also be captured by the proxy. Link-local and
multicast traffic remains direct.
The `Ordered rules` editor adds one policy per line with `proxy`, `direct`, or
`block` actions. User rules are evaluated top to bottom after DNS hijacking,
loopback, and UDP safety rules and before the convenience direct exceptions.
The settings are saved under `.runtime\gui-settings.json` when you start,
close, or press `Save profile`. `Guide` explains the input syntax and mode
tradeoffs, while `Folder` opens runtime logs and generated configuration.

Validate the generated config with the real engine:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\Check-ProxyBridgeRS.ps1 -Socks 127.0.0.1:10808
```

Run a preflight report:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\Doctor-ProxyBridgeRS.ps1 -Socks 127.0.0.1:10808 -AllowTcpOnly
```

The important doctor lines are:

- `SOCKS listening: yes`
- `SOCKS5 no-auth: yes`
- `SOCKS5 TCP CONNECT: yes`
- `SOCKS5 UDP associate: yes`
- `SOCKS5 UDP relay: yes` for true UDP/all-app coverage
- `Mode validation: ok`
- `Wintun: ...\wintun.dll`
- `Owned engine already running: no`
- `Config check: ok`

Run an elevated live proof test:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\Test-LiveProxyBridgeRS.ps1 -Socks 127.0.0.1:10808 -AllowTcpOnly
```

The live test temporarily starts the TUN tunnel, checks repeated `curl.exe` requests with no explicit proxy against repeated `curl.exe --socks5-hostname 127.0.0.1:10808` requests, verifies normal hostname HTTPS, and then stops the tunnel.
It prints average and max timings for explicit SOCKS versus TUN so latency spikes are visible.
It also prints Windows interface, default-route, and `ProxyBridgeRS` split-route snapshots after TUN startup so route installation problems are visible in the same output.
Temporary engine logs are written under `.runtime\runtime\logs` when using the helper scripts.
For true all-app coverage, the live test requires SOCKS5 UDP relay, not only a successful UDP ASSOCIATE handshake. If doctor reports `SOCKS5 UDP relay: no`, enable UDP relay on the v2rayN/Xray local SOCKS listener, use a local proxy port that really relays SOCKS5 UDP, or run TCP-only mode for browser-style traffic.

Increase the smoke sample size:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\Test-LiveProxyBridgeRS.ps1 -Socks 127.0.0.1:10808 -AllowTcpOnly -SmokeIterations 10
```

See `RELEASE_CHECKLIST.md` before publishing a GitHub release.

Add explicit direct exceptions from PowerShell:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\Start-ProxyBridgeRS.ps1 `
  -Socks 127.0.0.1:10808 -AllowTcpOnly -BypassProcess game.exe `
  -BypassIp 192.168.50.0/24 -BypassDomain .lan -BypassPort 8000:8100
```

For custom exceptions, call the CLI directly with repeatable options:

```powershell
.\target\release\proxybridge-rs.exe run --socks 127.0.0.1:10808 `
  --allow-tcp-only --bypass-process game.exe --bypass-ip 192.168.50.0/24 `
  --bypass-domain .lan --bypass-port 8000:8100
```

`--bypass-process` accepts executable names only, not paths. `--bypass-ip`
requires valid IPv4 or IPv6 CIDR notation. `--bypass-domain` accepts exact
domains such as `example.com` or suffixes such as `.example.com`. Prefix
`*.` is also accepted. `--bypass-port` accepts a port or inclusive range such
as `443` or `8000:8100`. Invalid values are rejected before the tunnel starts.

Add ordered proxy/direct/block rules from PowerShell:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\Start-ProxyBridgeRS.ps1 `
  -Socks 127.0.0.1:10808 -AllowTcpOnly `
  -Rule "block domain=ads.example.com" `
  -Rule "direct process=game.exe" `
  -Rule "proxy port=443"
```

Supported rule forms are `process=game.exe`, `ip=192.168.50.0/24`,
`domain=example.com`, `domain=.example.com` (suffix), `port=443`,
`port=8000:8100`, and `network=tcp|udp|icmp`. Blank lines and lines beginning
with `#` are ignored. The first matching user rule wins. DNS hijacking is
evaluated first, followed by built-in loopback and proxy-engine bypasses; the
TCP-only/QUIC UDP guards also remain before user rules so a custom rule cannot
create a routing loop or silently defeat the selected fail-closed mode.

Start the tunnel:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\Start-ProxyBridgeRS.ps1 -Socks 127.0.0.1:10808 -AllowTcpOnly
```

Stop the tunnel with `Ctrl+C` in the same terminal.
Starting a second copy with the same bundled engine is blocked so stale TUN sessions do not compete with the new one.

Stop a stale owned engine:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\Stop-ProxyBridgeRS.ps1
```

This only targets the bundled `sing-box.exe` path used by ProxyBridge RS.

## Defaults

- TUN mode is always used.
- The native GUI is available as `target\release\proxybridge-gui.exe`.
- The GUI starts in TCP-only mode by default for stable Chrome/Firefox/Telegram-style traffic with v2rayN setups that do not relay SOCKS5 UDP.
- DNS-via-proxy is off by default because it caused browsing failures in earlier testing.
- QUIC is blocked by default so Chrome/Firefox fall back to TCP, which is more consistently proxied through a SOCKS outbound.
- Already-open Chrome, Edge, Firefox, Brave, Opera, Vivaldi, and Telegram TCP sessions are reset shortly after start so they reconnect through TUN without closing the apps.
- IPv4 and IPv6 TUN addresses are configured.
- Full-capture split routes are configured for IPv4 and IPv6 (`0.0.0.0/1`, `128.0.0.0/1`, `::/1`, `8000::/1`).
- The default TUN MTU is 1500 for reliable operation across Wi-Fi, VPN, and virtual adapters; `--mtu` accepts an explicit 576-9000 override.
- RFC1918/private, CGNAT, link-local, multicast, and unique-local IPv6 destinations stay on the local network by default instead of being sent to the upstream SOCKS server. Enable `--proxy-local-networks` to capture private/CGNAT/ULA ranges intentionally; link-local and multicast remain direct.
- The default engine log level is `warn` to avoid unnecessary connection-log overhead during normal use.
- TCP-only mode uses sing-box's system TUN stack to avoid unnecessary UDP-stack overhead; full UDP mode uses the mixed stack.
- Ordered `proxy`, `direct`, and `block` rules are available for processes, IP CIDRs, domains, ports, and transport protocols.

## Coverage Notes

This app uses sing-box TUN instead of the old ProxyBridge relay path, which gives broad whole-machine route capture without per-app proxy rules. It is not a claim of measured superiority over mature products: Proxifier has a more mature Windows lifecycle and observability layer, while Clash Verge Rev has a broader management UI and core ecosystem.

Compared with Proxifier-style WFP proxying, this design captures IP routing instead of only hooking socket connections. That is better for broad coverage, but SOCKS itself is still the upstream constraint: TCP is the reliable path, while UDP depends on whether the local v2rayN/Xray SOCKS listener accepts UDP ASSOCIATE. The `doctor` command checks this directly.

The practical implementation options are:

- **TUN/Wintun:** the current choice for broad Windows IP capture. It is simple to deploy with sing-box and works well for TCP, but it still depends on the upstream SOCKS protocol and must coexist with Windows routing, VPNs, and virtual adapters.
- **WinDivert relay:** the official ProxyBridge-style packet interception path. It can express packet rules directly, but a custom user-mode TCP/UDP relay has more state, reinjection, fragmentation, and shutdown failure modes.
- **WFP redirection:** the strongest long-term option for per-process connection attribution and native Windows policy. It requires a signed kernel callout driver, installer, update path, and much broader compatibility testing.
- **System proxy:** useful for browsers and applications that honor HTTP/SOCKS settings, but it is not whole-device capture and misses applications that open sockets directly.

For this product goal, TUN is the best current tradeoff. WFP is the next architectural step only if precise per-process telemetry, proxy chains, or Windows-service operation becomes more important than a small, maintainable deployment.

No SOCKS-based design can transparently forward every possible Windows packet type. ICMP, broadcast/multicast discovery, and UDP applications require upstream support or a different transport. With a TCP-only upstream, TCP-only mode intentionally rejects UDP so it cannot silently leak.

## Advanced Flags

Use DNS through the proxy:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\Start-ProxyBridgeRS.ps1 -Socks 127.0.0.1:10808 -DnsViaProxy
```

Allow QUIC/HTTP3 UDP:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\Start-ProxyBridgeRS.ps1 -Socks 127.0.0.1:10808 -AllowQuic
```

Skip reconnecting already-open browsers:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\Start-ProxyBridgeRS.ps1 -Socks 127.0.0.1:10808 -NoReconnectApps
```

Run knowingly in TCP-only mode:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\Start-ProxyBridgeRS.ps1 -Socks 127.0.0.1:10808 -AllowTcpOnly
```

TCP-only mode is useful for browser-style traffic when your local SOCKS port refuses UDP ASSOCIATE, but it does not satisfy the all-app goal because UDP-heavy applications will fail. TCP-only mode also blocks remaining UDP after DNS handling so traffic does not silently leak or stall through an upstream SOCKS server without UDP.

Capture private LAN and virtual-network destinations through the proxy:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\Start-ProxyBridgeRS.ps1 -Socks 127.0.0.1:10808 -AllowTcpOnly -ProxyLocalNetworks
```

Increase logs while diagnosing:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\Start-ProxyBridgeRS.ps1 -Socks 127.0.0.1:10808 -LogLevel info
```

Manually reset existing browser/chat TCP sessions:

```powershell
$env:PROXYBRIDGE_RS_HOME = Join-Path (Get-Location) ".runtime"
.\target\release\proxybridge-rs.exe reset-browsers
```

## Runtime Files

The helper scripts set `PROXYBRIDGE_RS_HOME` to `.runtime` inside this project. Without that variable, the app uses `%LOCALAPPDATA%\ProxyBridgeRS`.
Prefer the helper scripts for normal use so Start, Stop, Doctor, and Live Test all operate on the same runtime home.

The app auto-downloads sing-box `1.13.14` and Wintun `0.14.1` on first use, validates the Wintun archive hash before extracting `wintun.dll`, and validates generated config with `sing-box check` before starting the tunnel.
The sing-box archive is also hash-verified before extraction. See
`THIRD_PARTY.md` for the upstream component links and distribution note.
