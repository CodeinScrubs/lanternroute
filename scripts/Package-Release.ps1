param(
    [string]$Version = "0.3.0"
)

$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $PSScriptRoot
$Release = Join-Path $Root "target\release"
$PackageRoot = Join-Path $Root "target\package"
$Stage = Join-Path $PackageRoot "LanternRoute-$Version-windows-x64"
$Archive = Join-Path $PackageRoot "LanternRoute-$Version-windows-x64.zip"
$Checksums = Join-Path $PackageRoot "SHA256SUMS.txt"
$PackageRelease = Join-Path $Stage "target\release"

$cargoText = Get-Content (Join-Path $Root "Cargo.toml") -Raw
$cargoVersionMatch = [regex]::Match($cargoText, '(?m)^version\s*=\s*"([^"]+)"')
if (!$cargoVersionMatch.Success) {
    throw "Could not read package version from Cargo.toml."
}
if ($cargoVersionMatch.Groups[1].Value -ne $Version) {
    throw "Package version $Version does not match Cargo.toml version $($cargoVersionMatch.Groups[1].Value)."
}

$changelog = Get-Content (Join-Path $Root "CHANGELOG.md") -Raw
if ($changelog -notmatch "(?m)^##\s+$([regex]::Escape($Version))\s*$") {
    throw "CHANGELOG.md has no release section for version $Version."
}

foreach ($name in @("lanternroute-gui.exe", "lanternroute.exe")) {
    $path = Join-Path $Release $name
    if (!(Test-Path -LiteralPath $path)) {
        throw "Release binary not found: $path. Run scripts\Build-Release.ps1 first."
    }
}

if (Test-Path -LiteralPath $PackageRoot) {
    Remove-Item -LiteralPath $PackageRoot -Recurse -Force
}
New-Item -ItemType Directory -Path $PackageRelease -Force | Out-Null

Copy-Item (Join-Path $Release "lanternroute-gui.exe") $PackageRelease
Copy-Item (Join-Path $Release "lanternroute.exe") $PackageRelease
Copy-Item (Join-Path $Root "scripts") (Join-Path $Stage "scripts") -Recurse
Copy-Item (Join-Path $Root "README.md") $Stage
Copy-Item (Join-Path $Root "LICENSE") $Stage
Copy-Item (Join-Path $Root "CHANGELOG.md") $Stage
Copy-Item (Join-Path $Root "RELEASE_CHECKLIST.md") $Stage
Copy-Item (Join-Path $Root "ARCHITECTURE.md") $Stage
Copy-Item (Join-Path $Root "THIRD_PARTY.md") $Stage
Copy-Item (Join-Path $Root "SECURITY.md") $Stage
Copy-Item (Join-Path $Root "SUPPORT.md") $Stage
Copy-Item (Join-Path $Root "CODE_OF_CONDUCT.md") $Stage

Compress-Archive -Path (Join-Path $Stage "*") -DestinationPath $Archive -CompressionLevel Optimal

Add-Type -AssemblyName System.IO.Compression.FileSystem
$zip = [System.IO.Compression.ZipFile]::OpenRead($Archive)
try {
    $entries = @($zip.Entries | ForEach-Object { $_.FullName.Replace("\", "/") })
    $requiredEntries = @(
        "target/release/lanternroute-gui.exe",
        "target/release/lanternroute.exe",
        "scripts/Install-LanternRoute.ps1",
        "scripts/Uninstall-LanternRoute.ps1",
        "README.md",
        "LICENSE",
        "CHANGELOG.md"
    )
    foreach ($entry in $requiredEntries) {
        if ($entries -notcontains $entry) {
            throw "Release archive is missing required entry: $entry"
        }
    }
} finally {
    $zip.Dispose()
}

$hash = (Get-FileHash -Algorithm SHA256 -LiteralPath $Archive).Hash.ToLowerInvariant()
Set-Content -LiteralPath $Checksums -Value "$hash  $(Split-Path -Leaf $Archive)" -Encoding ascii

Write-Host "Package: $Archive"
Write-Host "SHA256:  $hash"
