param(
    [string]$InstallDir = (Join-Path $env:LOCALAPPDATA "Programs\LanternRoute"),
    [switch]$RemoveRuntime
)

$ErrorActionPreference = "Stop"

if (Get-Process -Name "lanternroute-gui" -ErrorAction SilentlyContinue) {
    throw "Close the LanternRoute GUI before uninstalling."
}

$Cli = Join-Path $InstallDir "lanternroute.exe"
if (Test-Path -LiteralPath $Cli -PathType Leaf) {
    Write-Host "Stopping any active LanternRoute tunnel..."
    $Process = Start-Process `
        -FilePath $Cli `
        -ArgumentList "stop" `
        -Verb RunAs `
        -Wait `
        -PassThru
    if ($Process.ExitCode -ne 0) {
        throw "LanternRoute stop failed with exit code $($Process.ExitCode). Run Stop from the GUI, then retry."
    }
}

$DesktopShortcut = Join-Path ([Environment]::GetFolderPath("Desktop")) "LanternRoute.lnk"
$StartMenuDir = Join-Path ([Environment]::GetFolderPath("Programs")) "LanternRoute"
Remove-Item -LiteralPath $DesktopShortcut -Force -ErrorAction SilentlyContinue
Remove-Item -LiteralPath $StartMenuDir -Recurse -Force -ErrorAction SilentlyContinue

if (Test-Path -LiteralPath $InstallDir) {
    Remove-Item -LiteralPath $InstallDir -Recurse -Force
}

if ($RemoveRuntime) {
    $RuntimeDir = Join-Path $env:LOCALAPPDATA "LanternRoute"
    Remove-Item -LiteralPath $RuntimeDir -Recurse -Force -ErrorAction SilentlyContinue
    Write-Host "LanternRoute and its runtime data were removed."
} else {
    Write-Host "LanternRoute was removed. Runtime settings remain in %LOCALAPPDATA%\LanternRoute."
    Write-Host "Use -RemoveRuntime to delete settings, logs, and downloaded engine files too."
}
