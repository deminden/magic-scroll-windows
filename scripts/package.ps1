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
    $zip = Join-Path $release "magic-scroll-windows-x64-v$Version.zip"
    Compress-Archive -LiteralPath $package -DestinationPath $zip -CompressionLevel Optimal
    "$((Get-FileHash -LiteralPath $zip -Algorithm SHA256).Hash.ToLowerInvariant())  $([IO.Path]::GetFileName($zip))" |
        Set-Content -LiteralPath (Join-Path $release 'SHA256SUMS.txt') -Encoding utf8
    @"
Enable touch scrolling on the USB-C Magic Mouse using Apple's unchanged signed driver.

**Download the Windows x64 ZIP below, extract it, and double-click magic-scroll-setup.exe.**
Choose 1 to download and check; then run setup as administrator and choose 2 to install.
No Rust, separate 7-Zip installation, subscription or developer certificate is required.

This experimental release was tested on one Windows 11 Home x64 computer with
Memory Integrity enabled. Vertical scrolling and reconnection after two minutes
off worked. Horizontal wheel input was recorded; horizontal content scrolling,
sleep/wake, cold reboot and removal still need physical tests.

Apple's scrolling engine is unchanged. Its inspected INF omits USB-C PID 0323;
this tool supplies the attachment and checks. Apple files are downloaded separately.

The Rust executables are unsigned. Keep Windows protection enabled and retain
the local removal journal. SHA256SUMS.txt covers the ZIP; the ZIP includes hashes
for both executables, the MIT licence, dependency notices and detailed instructions.
"@ | Set-Content -LiteralPath (Join-Path $release 'RELEASE_NOTES.md') -Encoding utf8
    Write-Output "Ready: $zip"
} finally {
    Pop-Location
}
