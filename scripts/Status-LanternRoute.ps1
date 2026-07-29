$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $PSScriptRoot
$env:LANTERNROUTE_HOME = Join-Path $Root ".runtime"
$Exe = Join-Path $Root "target\release\lanternroute.exe"

if (!(Test-Path -LiteralPath $Exe -PathType Leaf)) {
    throw "LanternRoute release binary not found: $Exe"
}

& $Exe status
exit $LASTEXITCODE
