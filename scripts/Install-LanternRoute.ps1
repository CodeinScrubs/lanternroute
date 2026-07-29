param(
    [string]$InstallDir = (Join-Path $env:LOCALAPPDATA "Programs\LanternRoute"),
    [switch]$NoDesktopShortcut
)

$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $PSScriptRoot
$Release = Join-Path $Root "target\release"
$GuiSource = Join-Path $Release "lanternroute-gui.exe"
$CliSource = Join-Path $Release "lanternroute.exe"
$UninstallerSource = Join-Path $PSScriptRoot "Uninstall-LanternRoute.ps1"

foreach ($path in @($GuiSource, $CliSource, $UninstallerSource)) {
    if (!(Test-Path -LiteralPath $path -PathType Leaf)) {
        throw "Required package file not found: $path"
    }
}

if (Get-Process -Name "lanternroute", "lanternroute-gui" -ErrorAction SilentlyContinue) {
    throw "Close LanternRoute before installing or upgrading it."
}

New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
Copy-Item -LiteralPath $GuiSource -Destination $InstallDir -Force
Copy-Item -LiteralPath $CliSource -Destination $InstallDir -Force
Copy-Item -LiteralPath $UninstallerSource -Destination $InstallDir -Force

$Shell = New-Object -ComObject WScript.Shell
$ProgramsDir = [Environment]::GetFolderPath("Programs")
$StartMenuDir = Join-Path $ProgramsDir "LanternRoute"
New-Item -ItemType Directory -Path $StartMenuDir -Force | Out-Null

function New-LanternRouteShortcut {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Target,
        [string]$Arguments = ""
    )

    $Shortcut = $Shell.CreateShortcut($Path)
    $Shortcut.TargetPath = $Target
    $Shortcut.Arguments = $Arguments
    $Shortcut.WorkingDirectory = $InstallDir
    $Shortcut.Description = "Whole-device Windows routing through a local SOCKS5 proxy"
    $Shortcut.Save()
}

$GuiTarget = Join-Path $InstallDir "lanternroute-gui.exe"
New-LanternRouteShortcut `
    -Path (Join-Path $StartMenuDir "LanternRoute.lnk") `
    -Target $GuiTarget

$PowerShell = (Get-Command powershell.exe).Source
$UninstallerTarget = Join-Path $InstallDir "Uninstall-LanternRoute.ps1"
$UninstallArgs = "-NoProfile -ExecutionPolicy Bypass -File `"$UninstallerTarget`""
New-LanternRouteShortcut `
    -Path (Join-Path $StartMenuDir "Uninstall LanternRoute.lnk") `
    -Target $PowerShell `
    -Arguments $UninstallArgs

if (!$NoDesktopShortcut) {
    $DesktopDir = [Environment]::GetFolderPath("Desktop")
    New-LanternRouteShortcut `
        -Path (Join-Path $DesktopDir "LanternRoute.lnk") `
        -Target $GuiTarget
}

Write-Host "LanternRoute installed to $InstallDir"
Write-Host "Start it from the Start menu or desktop shortcut."
