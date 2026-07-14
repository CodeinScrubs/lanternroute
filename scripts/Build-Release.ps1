param()

$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $PSScriptRoot
$env:CARGO_HOME = Join-Path $Root ".tools\cargo"
$env:RUSTUP_HOME = Join-Path $Root ".tools\rustup"
$env:PATH = "C:\msys64\ucrt64\bin;$env:CARGO_HOME\bin;$env:PATH"

# The bundled GNU toolchain can use Rust's LLD reliably even when the system
# MinGW binutils version changes independently of Rust.
$RustLld = Get-ChildItem (Join-Path $env:RUSTUP_HOME "toolchains") -Filter "rust-lld.exe" -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1
if ($null -ne $RustLld) {
    $env:CARGO_TARGET_X86_64_PC_WINDOWS_GNU_LINKER = $RustLld.FullName
}

$Cargo = Join-Path $env:CARGO_HOME "bin\cargo.exe"
if (!(Test-Path -LiteralPath $Cargo)) {
    $CargoCommand = Get-Command cargo.exe -ErrorAction SilentlyContinue
    if ($null -eq $CargoCommand) {
        throw "Rust toolchain not found. Install Rust or place cargo.exe at $Cargo"
    }
    $Cargo = $CargoCommand.Source
}

Push-Location $Root
try {
    & $Cargo build --locked --release
}
finally {
    Pop-Location
}
