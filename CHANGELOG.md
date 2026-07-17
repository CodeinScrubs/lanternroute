# Changelog

## 0.1.0

First public release.

### Core

- Whole-device Windows TUN routing through a local SOCKS5 endpoint using a
  pinned sing-box 1.13.14 engine and Wintun 0.14.1.
- Native DPI-aware Windows GUI with persistent profiles, an in-app guide, and
  automatic Administrator relaunch, plus a full CLI
  (`run`, `check`, `doctor`, `smoke-test`, `print-config`, `ensure-engine`,
  `stop`, `reset-browsers`) and PowerShell helper scripts.
- SHA-256 verification for the sing-box archive, sing-box executable, Wintun
  archive, and extracted Wintun DLL; engine version validation before start.

### Routing policy

- Ordered `proxy`, `direct`, and `block` rules for processes, CIDRs, domains,
  ports, and transport protocols, with protected DNS and fail-closed UDP
  precedence that user rules cannot override.
- Direct exceptions for processes, IP CIDRs, domains/suffixes, and
  ports/ranges alongside built-in loopback and proxy-engine bypasses.
- Explicit private-network capture policy: LAN/CGNAT/ULA ranges stay direct by
  default; `--proxy-local-networks` captures them intentionally.
- TCP-only mode blocks unproxyable UDP instead of leaking it; QUIC is blocked
  by default so browsers fall back to TCP.

### Diagnostics and lifecycle

- SOCKS5 probing that proves no-auth handshake, TCP CONNECT, UDP ASSOCIATE,
  and a real UDP relay round-trip; mode validation refuses configurations the
  upstream cannot honor.
- Elevated live smoke test comparing TUN egress against explicit SOCKS egress
  with per-request latency statistics, route snapshots, and competing-route
  detection.
- Route-readiness verification on start, and capture-route/interface cleanup
  verification after `run`, `smoke-test`, and `stop` so a terminated engine
  can never silently leave Windows without connectivity.
- Global controller lock, Windows Job Object cleanup of the engine process,
  stale-engine detection, and hardened GUI stop/close handling so startup
  races cannot orphan the TUN engine.
- Browser/chat TCP session reset (Chrome, Edge, Firefox, Brave, Opera,
  Vivaldi, Telegram) after routes are ready, hardened against transient
  Windows TCP-table buffer races.
- Smoke-test latency samples measure only the successful request, excluding
  retry backoff.

### Distribution

- Optimized release profile (LTO, single codegen unit, stripped symbols).
- CI (fmt, clippy `-D warnings`, tests, release build) and tag-driven release
  packaging with SHA-256 checksums.
- Publication, security, contribution, and architecture documentation, plus
  issue and pull-request templates.
