# Support

LanternRoute is a Windows-only whole-device TUN controller. Before opening an
issue:

1. Confirm that the local SOCKS5 endpoint works with an explicit client, for
   example `curl.exe --socks5-hostname 127.0.0.1:10808 https://api.ipify.org`.
2. Run `Doctor` with the same endpoint and record whether TCP CONNECT and UDP
   relay pass.
3. Run the elevated live test in `scripts\Test-LiveLanternRoute.ps1`.
4. Remove proxy credentials, subscription URLs, private IPs, and tokens from
   logs before sharing them.

Use GitHub Discussions for setup questions and feature ideas when available.
Use an issue for a reproducible defect. Security vulnerabilities belong in a
private GitHub security advisory; see `SECURITY.md`.

Remember that TCP-only mode cannot provide UDP application coverage. A local
SOCKS listener that accepts UDP ASSOCIATE but does not relay UDP is still a
TCP-only upstream for LanternRoute.
