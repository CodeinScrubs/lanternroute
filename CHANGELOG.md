# Changelog

## Unreleased

- Hardened browser TCP-table cleanup against transient Windows buffer races.
- Added SHA-256 verification for the pinned sing-box archive.
- Upgraded the pinned stable sing-box engine to 1.13.14.
- Added a responsive DPI-aware GUI with persistent profiles and an in-app guide.
- Added direct domain and destination-port exceptions alongside process and CIDR rules.
- Added ordered `proxy`, `direct`, and `block` rules for processes, CIDRs, domains, ports, and networks, with protected DNS and UDP safety precedence.
- Hardened GUI Stop and close handling so startup races cannot leave the controller or TUN engine behind.
- Added SOCKS5 TCP CONNECT proof, Wintun DLL hash validation, named controller serialization, and competing-route diagnostics.
- Added explicit private-network capture policy, safe 1500-byte MTU default, DNS bootstrap resolution, and atomic-ish profile replacement.
- Added publication, security, and continuous-integration documentation.

## 0.1.0

- Initial Windows Rust GUI and CLI release candidate.
- TUN routing through a local SOCKS5 endpoint using sing-box and Wintun.
- TCP-only diagnostics and explicit SOCKS5 UDP relay validation.
