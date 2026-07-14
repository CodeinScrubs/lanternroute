# Contributing

ProxyBridge RS is a Windows-only Rust application. Changes that affect route
capture, DNS, SOCKS probing, process bypasses, or engine cleanup need focused
tests and a clear failure-mode explanation.

The declared minimum Rust version is 1.85, matching Rust 2024 edition support.
CI is pinned to Rust 1.96.0 through `rust-toolchain.toml` for reproducible
release builds.

## Local verification

From an Administrator PowerShell when live routing is involved:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\Build-Release.ps1
$env:CARGO_HOME = Join-Path (Get-Location) ".tools\cargo"
$env:RUSTUP_HOME = Join-Path (Get-Location) ".tools\rustup"
& (Join-Path $env:CARGO_HOME "bin\cargo.exe") fmt --all -- --check
& (Join-Path $env:CARGO_HOME "bin\cargo.exe") test --locked --all-targets
& (Join-Path $env:CARGO_HOME "bin\cargo.exe") clippy --locked --all-targets -- -D warnings
```

Use `Doctor` before starting a real tunnel. Use `Test-LiveProxyBridgeRS.ps1`
only when the local SOCKS endpoint is available, and report whether the test
was TCP-only or included a proven SOCKS5 UDP relay.

Do not commit `.runtime`, `.tools`, `target`, generated logs, proxy endpoints
containing credentials, or downloaded engine binaries.
