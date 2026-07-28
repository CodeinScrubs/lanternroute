param()

$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $PSScriptRoot
$Exe = Join-Path $Root "target\release\lanternroute.exe"
if (!(Test-Path -LiteralPath $Exe)) {
    throw "Release binary not found. Run scripts\Build-Release.ps1 first."
}

$Principal = [Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()
$IsAdmin = $Principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (!$IsAdmin) {
    throw "Stopping an elevated TUN engine needs Administrator. Open PowerShell as Administrator and run this script again."
}

$env:LANTERNROUTE_HOME = Join-Path $Root ".runtime"

& $Exe stop
