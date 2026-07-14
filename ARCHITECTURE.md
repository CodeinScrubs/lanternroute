# Architecture and product guide

## What the app uses

ProxyBridge RS is a Windows controller around a pinned sing-box TUN data
plane:

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

- **Rust controller:** owns the GUI, CLI, validation, engine download checks,
  route readiness checks, process cleanup, and shutdown lifecycle.
- **Wintun:** provides the Layer-3 virtual network adapter.
- **sing-box TUN:** installs the capture routes and translates captured TCP or
  UDP traffic into the configured outbound.
- **SOCKS5 outbound:** is the upstream transport in this project. The local
  port is usually `127.0.0.1:10808` from v2rayN.
- **Direct rules:** loopback and proxy-engine processes bypass the tunnel to
  prevent a routing loop. Users can add more process names, CIDRs, domains,
  and ports.

sing-box documents `auto_route` as setting the default route to TUN,
`route_address` as the custom capture route list, and `strict_route` as a
Windows leak-prevention mechanism. Its documentation also warns that strict
routing can affect applications such as VirtualBox, which is why direct
exceptions matter. See the [sing-box TUN documentation](https://sing-box.sagernet.org/configuration/inbound/tun/).

## Available modes

| Option | Default | Meaning |
| --- | --- | --- |
| TCP-only | On in GUI | Captures TCP and rejects remaining UDP. Use when the SOCKS listener has no working UDP relay. |
| Full UDP | Off in GUI | Allows UDP handling, but only works correctly when Doctor proves a real SOCKS5 UDP relay. |
| DNS local | On | DNS is resolved by the normal Windows resolver path and DNS traffic is handled locally. |
| DNS via proxy | Off | Uses HTTPS DNS through the proxy. Useful for DNS restrictions, but adds another dependency and can fail with some upstreams. |
| Block QUIC | On | Rejects UDP/443 so browsers use TCP, which is more reliable with TCP-only SOCKS profiles. |
| Allow QUIC | Off | Permits HTTP/3 when the upstream UDP path is known to work. |
| Reconnect existing apps | On | Resets selected established TCP sessions after routes are ready so browsers can reconnect without being closed. |
| Bypass apps | Empty except built-ins | Direct-routes executable names that must not be captured. |
| Bypass CIDRs | Empty except loopback | Direct-routes networks such as a LAN, printer, VM, or local service. |
| Proxy local networks | Off | Captures private IPv4/CGNAT/unique-local IPv6 destinations through SOCKS; link-local and multicast remain direct. |
| Direct domains | Empty | Direct-routes exact domains or suffixes such as `example.com` or `.lan`. |
| Direct ports | Empty | Direct-routes destination ports or ranges such as `443` or `8000:8100`. |
| Ordered rules | Empty | First-match `proxy`, `direct`, or `block` policies for process, IP, domain, port, or network. |

## How to write exceptions

### App names

Use the executable filename only, with the `.exe` suffix, and separate values
with commas:

```text
xray.exe, v2rayN.exe, game.exe
```

Do not enter a full path such as `C:\\Apps\\game.exe`. Find the actual name in
Task Manager -> Details. The match is against the process name, not the window
title or a shortcut name. ProxyBridge RS always includes its own engine and
known proxy-engine names automatically.

### IP networks

Use CIDR notation: an address followed by `/` and a prefix length.

```text
192.168.1.0/24    # one LAN
192.168.1.25/32   # one IPv4 address
10.0.0.0/8        # private IPv4 range
fd00::/8          # private IPv6 range
::1/128           # one IPv6 loopback address
```

Do not enter a bare address such as `192.168.1.25`; write
`192.168.1.25/32`. Invalid CIDRs are rejected before the tunnel starts.

### Domains and ports

Domains use exact names or suffixes. `example.com` matches that domain, while
`.example.com` and `*.example.com` match the suffix. Ports accept one number or
an inclusive range such as `443` or `8000:8100`.

### Ordered policies

The GUI and CLI accept one rule per line or repeated `--rule` arguments:

```text
block domain=ads.example.com
direct process=game.exe
proxy port=443
block network=udp
```

Supported matchers are `process`, `ip`/`cidr`, `domain`, `port`, and `network`.
Domain values beginning with `.` or `*.` are suffix matches. The first user
rule that matches wins. The generated route list deliberately places DNS
hijacking first, then the built-in loopback and proxy-engine bypasses, then
QUIC/TCP-only UDP guards, then user rules, then convenience direct exceptions,
and finally the proxy default. This means a user rule cannot capture the local
SOCKS engine or override DNS handling, and TCP-only mode remains fail-closed for
UDP even when a user also adds a direct process or port exception.

## Comparison with other approaches

### Proxifier-style interception

Proxifier advertises per-application, hostname, IP, and port rules, direct/
block/proxy actions, proxy chains/failover, live connection information, and a
more mature Windows deployment model. Its implementation is proprietary, so
we should compare observable behavior rather than claim an exact internal
architecture. See the [official Proxifier feature list](https://www.proxifier.com/features.html).

This project currently has a stronger whole-device route model and a simpler
open-source deployment, but it does not yet match Proxifier's connection
table, proxy chains, service/tray integration, or signed installer. Its ordered
rule editor now covers the core process/IP/domain/port/protocol actions, but it
does not yet have Proxifier's mature connection-table UX.

### Official ProxyBridge

The official ProxyBridge project describes Windows interception based on
WinDivert and supports process/rule-oriented TCP and UDP routing. WinDivert is
flexible for packet capture and modification, but a user-mode relay must handle
packet state, reinjection, fragmentation, shutdown, and driver compatibility
carefully. See the [official ProxyBridge repository](https://github.com/InterceptSuite/ProxyBridge).

Our TUN approach lets the operating system and sing-box handle much of the
packet and route machinery. That is why it has been more stable in the Chrome,
Firefox, Telegram, IPv4, IPv6, and TCP smoke tests performed on this machine.
It is not automatically better for every workload: upstream SOCKS UDP support
remains a hard limit.

### WFP redirect driver

Windows Filtering Platform can redirect connections through a callout driver,
which is the strongest long-term option for per-process connection telemetry,
blocking, and precise rules. Microsoft recommends user-mode management when
standard filtering is sufficient and reserves callout drivers for behavior
that needs kernel processing. A WFP driver also brings signing, installation,
crash, update, and compatibility work. See Microsoft's [WFP architecture](https://learn.microsoft.com/en-us/windows-hardware/drivers/network/windows-filtering-platform-architecture-overview)
and [callout guidance](https://learn.microsoft.com/en-us/windows-hardware/drivers/network/callout-driver-programming-considerations).

## Best improvement path

1. Keep the current TUN path as the default whole-device mode.
2. Keep the ordered `proxy`, `direct`, and `block` rule editor aligned with
   sing-box route capabilities and add clearer per-rule diagnostics.
3. Add a live connection table and traffic counters sourced from the engine,
   with filtering and a clear rule/outbound explanation.
4. Add multiple SOCKS profiles, latency checks, failover, and a deliberate
   "fail closed" policy when the upstream disappears.
5. Add a tray controller and a Windows service/helper so the data plane can
   survive GUI restarts without orphaned routes.
6. Add a signed installer, update channel, crash logs, and a clean uninstall
   path.
7. Test real UDP profiles, sleep/resume, Wi-Fi changes, VPN coexistence,
   Hyper-V/WSL/VirtualBox, games, services, and multiple user sessions.

There is no local setting that can manufacture SOCKS5 UDP relay support. If the
v2rayN/Xray upstream only carries TCP, the honest high-reliability behavior is
TCP-only mode with UDP rejected, not a silent direct leak or a fake claim of
all-protocol coverage.
