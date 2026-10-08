# SPDX-License-Identifier: MIT
# Package only our executables and notices; never include Apple's downloads or journals.
[CmdletBinding()]
param(
    [Parameter(Mandatory)][ValidatePattern('^\d+\.\d+\.\d+$')][string]$Version,
    [string]$BinaryDirectory = 'target/release'
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$root = Split-Path -Parent $PSScriptRoot
Push-Location $root
try {
    $metadata = cargo metadata --format-version 1 --locked | ConvertFrom-Json
    if ($LASTEXITCODE -ne 0) { throw 'Cargo metadata failed' }
    $members = @($metadata.packages | Where-Object { $metadata.workspace_members -contains $_.id })
    foreach ($member in $members) {
        if ($member.version -ne $Version) { throw 'Package version does not match Cargo' }
    }
    $stage = Join-Path $root "dist/package-v$Version"
    $release = Join-Path $root 'dist/release'
    if ((Test-Path -LiteralPath $stage) -or (Test-Path -LiteralPath $release)) {
        throw 'Package output already exists. Inspect it before creating a new package.'
    }
    $package = Join-Path $stage 'magic-scroll'
    $notices = Join-Path $package 'dependency-licences'
    New-Item -ItemType Directory -Path $notices -Force | Out-Null
    foreach ($name in @('magic-scroll.exe', 'magic-scroll-setup.exe')) {
        Copy-Item -LiteralPath (Join-Path $BinaryDirectory $name) -Destination $package
    }
    foreach ($name in @('LICENSE', 'README.md', 'THIRD_PARTY.md')) {
        Copy-Item -LiteralPath (Join-Path $root $name) -Destination $package
    }
    Copy-Item -LiteralPath (Join-Path $root 'docs') -Destination $package -Recurse
    $summary = @('# Dependency licences', '', 'Package | Declared licence', '---|---')
    foreach ($dependency in ($metadata.packages | Where-Object { $null -ne $_.source } | Sort-Object name, version)) {
        $summary += "$($dependency.name) $($dependency.version) | $($dependency.license)"
        $directory = Split-Path -Parent $dependency.manifest_path
        $files = @(Get-ChildItem -LiteralPath $directory -File | Where-Object { $_.Name -match '^(LICENSE|COPYING|UNLICENSE)' })
        if ($dependency.license_file) {
            $files += Get-Item -LiteralPath (Join-Path $directory $dependency.license_file)
        }
        if ($files.Count -eq 0) { throw "Missing licence files for $($dependency.name)" }
        foreach ($file in ($files | Sort-Object FullName -Unique)) {
            Copy-Item -LiteralPath $file.FullName -Destination (Join-Path $notices "$($dependency.name)-$($dependency.version)-$($file.Name)")
        }
    }
    $summary | Set-Content -LiteralPath (Join-Path $notices 'README.md') -Encoding utf8
    $sysroot = rustc --print sysroot
    if ($LASTEXITCODE -ne 0) { throw 'Rust sysroot query failed' }
    $copyright = Join-Path $sysroot 'share/doc/rust/COPYRIGHT.html'
    Copy-Item -LiteralPath $copyright -Destination (Join-Path $notices 'Rust-COPYRIGHT.html')
    $checksums = foreach ($file in (Get-ChildItem -LiteralPath $package -Filter '*.exe' -File | Sort-Object Name)) {
        "$((Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash.ToLowerInvariant())  $($file.Name)"
    }
    $checksums | Set-Content -LiteralPath (Join-Path $package 'SHA256SUMS.txt') -Encoding utf8
    New-Item -ItemType Directory -Path $release | Out-Null
    # A consistent asset name lets the README always point to the latest download.
    $zip = Join-Path $release 'magic-scroll-windows-x64.zip'
    Compress-Archive -LiteralPath $package -DestinationPath $zip -CompressionLevel Optimal
    "$((Get-FileHash -LiteralPath $zip -Algorithm SHA256).Hash.ToLowerInvariant())  $([IO.Path]::GetFileName($zip))" |
        Set-Content -LiteralPath (Join-Path $release 'SHA256SUMS.txt') -Encoding utf8
    @"
USB-C Magic Mouse scrolling on Windows, with ready-to-run Rust setup tools.

## [Download for Windows (x64)](https://github.com/deminden/magic-scroll-windows/releases/download/v$Version/magic-scroll-windows-x64.zip)

- Ready-to-run binaries: no compiler or terminal commands.
- Automatic attachment of Apple's signed driver to the paired mouse.
- Verified downloads from Apple and 7-zip.org; no separate 7-Zip installation.
- Free and MIT licensed, with no subscription or background app.
- Windows protection settings stay intact.
- Installation, testing, and removal in one setup menu.

### Start in three steps

1. Download the ZIP above and extract it.
2. Open **magic-scroll-setup.exe** and choose **1: Download and check**.
3. Run setup as administrator, choose **2: Install**, then type **INSTALL**.

Try scrolling in a page or document. Open **magic-scroll.exe** to see mouse-input counts.

Vertical touch scrolling and Bluetooth reconnection were confirmed on Windows 11
Home x64 with Memory Integrity enabled. Horizontal wheel input, pointer movement,
and left/right clicks were also recorded. See the [test results](https://github.com/deminden/magic-scroll-windows/blob/v$Version/docs/VALIDATION.md).

Apple's installer omits PID 0323. Magic Scroll handles that attachment directly,
using the unchanged signed driver.

Keep the setup folder after installation so you can use the removal option later.

**Included:** setup and test executables, instructions, licence notices, and checksums.
SHA256SUMS.txt covers the ZIP. Inside are hashes for both executables, the MIT
licence, dependency notices, and instructions. GitHub build provenance is also available.
"@ | Set-Content -LiteralPath (Join-Path $release 'RELEASE_NOTES.md') -Encoding utf8
    Write-Output "Ready: $zip"
} finally {
    Pop-Location
}
