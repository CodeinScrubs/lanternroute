param(
    [string]$Socks = "127.0.0.1:10808",
    [switch]$DnsViaProxy,
    [switch]$AllowQuic,
    [switch]$NoReconnectApps,
    [switch]$AllowTcpOnly,
    [switch]$ProxyLocalNetworks,
    [string[]]$BypassProcess = @(),
    [string[]]$BypassIp = @(),
    [string[]]$BypassDomain = @(),
    [string[]]$BypassPort = @(),
    [string[]]$Rule = @(),
    [byte]$SmokeIterations = 3,
    [string]$LogLevel = "warn"
)

$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $PSScriptRoot
$Exe = Join-Path $Root "target\release\proxybridge-rs.exe"
if (!(Test-Path -LiteralPath $Exe)) {
    throw "Release binary not found. Run scripts\Build-Release.ps1 first."
}

$Principal = [Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()
$IsAdmin = $Principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (!$IsAdmin) {
    throw "Live smoke test needs Administrator because it temporarily starts TUN routing."
}

$env:PROXYBRIDGE_RS_HOME = Join-Path $Root ".runtime"

$Args = @("smoke-test", "--socks", $Socks, "--log-level", $LogLevel, "--smoke-iterations", $SmokeIterations)
if ($DnsViaProxy) { $Args += "--dns-via-proxy" }
if ($AllowQuic) { $Args += "--allow-quic" }
if ($NoReconnectApps) { $Args += "--no-reconnect-apps" }
if ($AllowTcpOnly) { $Args += "--allow-tcp-only" }
if ($ProxyLocalNetworks) { $Args += "--proxy-local-networks" }
foreach ($process in $BypassProcess) { $Args += @("--bypass-process", $process) }
foreach ($cidr in $BypassIp) { $Args += @("--bypass-ip", $cidr) }
foreach ($domain in $BypassDomain) { $Args += @("--bypass-domain", $domain) }
foreach ($port in $BypassPort) { $Args += @("--bypass-port", $port) }
foreach ($rule in $Rule) { $Args += @("--rule", $rule) }

& $Exe @Args
