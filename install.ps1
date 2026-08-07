#Requires -Version 5.1
<#
.SYNOPSIS
    VectorLedger installer for Windows.

.DESCRIPTION
    Downloads the pre-built vledger.exe binary for Windows from GitHub Releases,
    verifies its SHA-256 checksum, and installs it to a directory on your PATH.

    If no pre-built binary is available for your architecture, the script falls
    back to building from source using Cargo (Rust 1.80+ required).

.PARAMETER Version
    Release tag to install, e.g. "v0.1.0".
    Defaults to the latest release from GitHub.

.PARAMETER InstallDir
    Directory to install vledger.exe into.
    Defaults to "$env:LOCALAPPDATA\vledger\bin" (no admin required).
    Use "C:\Program Files\vledger" for a system-wide install (requires admin).

.PARAMETER NoPathUpdate
    If specified, the installer will not add InstallDir to your PATH.

.EXAMPLE
    # Install latest release (run from PowerShell)
    irm https://raw.githubusercontent.com/pavondunbar/VectorLedger/main/install.ps1 | iex

.EXAMPLE
    # Install a specific version
    $env:VLEDGER_VERSION = "v0.1.0"
    irm https://raw.githubusercontent.com/pavondunbar/VectorLedger/main/install.ps1 | iex

.EXAMPLE
    # Install to a custom directory
    & ([scriptblock]::Create((irm https://raw.githubusercontent.com/pavondunbar/VectorLedger/main/install.ps1))) `
        -InstallDir "C:\Tools\vledger"

.NOTES
    Supported: Windows 10/11, Windows Server 2019/2022
    Architecture: x86_64 (AMD64) and ARM64
    Requires: PowerShell 5.1+ or PowerShell 7+
#>

[CmdletBinding()]
param(
    [string] $Version     = $env:VLEDGER_VERSION,
    [string] $InstallDir  = "",
    [switch] $NoPathUpdate
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# ── Constants ──────────────────────────────────────────────────────────────────

$Repo            = "pavondunbar/VectorLedger"
$Binary          = "vledger.exe"
$ReleasesApi     = "https://api.github.com/repos/$Repo/releases/latest"
$ReleasesDownload = "https://github.com/$Repo/releases/download"

# ── Colour helpers ─────────────────────────────────────────────────────────────

function Write-Info  { param($Msg) Write-Host "  info  $Msg" -ForegroundColor Cyan    }
function Write-Ok    { param($Msg) Write-Host "    ok  $Msg" -ForegroundColor Green   }
function Write-Warn  { param($Msg) Write-Host "  warn  $Msg" -ForegroundColor Yellow  }
function Write-Err   { param($Msg) Write-Host " error  $Msg" -ForegroundColor Red     }
function Write-Bold  { param($Msg) Write-Host $Msg            -ForegroundColor White  }

function Fail {
    param($Msg)
    Write-Err $Msg
    exit 1
}

# ── Architecture detection ─────────────────────────────────────────────────────

function Get-Arch {
    switch ($env:PROCESSOR_ARCHITECTURE) {
        "AMD64"  { return "x86_64"  }
        "ARM64"  { return "aarch64" }
        default  { Fail "Unsupported architecture: $env:PROCESSOR_ARCHITECTURE. Supported: AMD64, ARM64." }
    }
}

# ── Version resolution ─────────────────────────────────────────────────────────

function Resolve-Version {
    param([string] $RequestedVersion)

    if ($RequestedVersion -ne "") {
        if (-not $RequestedVersion.StartsWith("v")) { $RequestedVersion = "v$RequestedVersion" }
        return $RequestedVersion
    }

    Write-Info "Fetching latest release version from GitHub..."
    try {
        $headers  = @{ Accept = "application/vnd.github+json" }
        $response = Invoke-RestMethod -Uri $ReleasesApi -Headers $headers -UseBasicParsing
        return $response.tag_name
    } catch {
        Fail "Could not determine the latest release version: $_`nSet `$env:VLEDGER_VERSION manually and retry."
    }
}

# ── Install directory ──────────────────────────────────────────────────────────

function Resolve-InstallDir {
    param([string] $Dir)
    if ($Dir -ne "") { return $Dir }
    return Join-Path $env:LOCALAPPDATA "vledger\bin"
}

# ── Download helper ────────────────────────────────────────────────────────────

function Download-File {
    param([string] $Url, [string] $Dest)
    try {
        $ProgressPreference = "SilentlyContinue"   # speeds up Invoke-WebRequest significantly
        Invoke-WebRequest -Uri $Url -OutFile $Dest -UseBasicParsing
    } catch {
        throw "Download failed: $Url`n$_"
    }
}

# ── Checksum verification ──────────────────────────────────────────────────────

function Verify-Checksum {
    param([string] $FilePath, [string] $ChecksumFile)

    $fileName = Split-Path $FilePath -Leaf
    $lines    = Get-Content $ChecksumFile -ErrorAction SilentlyContinue
    $expected = $lines | Where-Object { $_ -match $fileName } | ForEach-Object { ($_ -split '\s+')[0] }

    if (-not $expected) {
        Write-Warn "No checksum entry found for $fileName — skipping verification."
        return
    }

    $actual = (Get-FileHash -Path $FilePath -Algorithm SHA256).Hash.ToLower()
    if ($actual -ne $expected.ToLower()) {
        Fail "Checksum mismatch for $fileName!`n  Expected : $expected`n  Actual   : $actual"
    }
    Write-Ok "Checksum verified."
}

# ── PATH update ────────────────────────────────────────────────────────────────

function Add-ToUserPath {
    param([string] $Dir)

    $currentPath = [Environment]::GetEnvironmentVariable("PATH", "User")
    if ($currentPath -split ";" | Where-Object { $_ -eq $Dir }) {
        return   # already present
    }

    $newPath = "$Dir;$currentPath"
    [Environment]::SetEnvironmentVariable("PATH", $newPath, "User")
    Write-Warn "$Dir added to your user PATH."
    Write-Warn "Restart your terminal (or run: `$env:PATH = `"$Dir;`$env:PATH`") to use vledger."
}

# ── Build from source fallback ─────────────────────────────────────────────────

function Build-FromSource {
    param([string] $VersionTag, [string] $DestDir)

    Write-Warn "No pre-built binary found for this platform. Attempting to build from source..."

    if (-not (Get-Command cargo -ErrorAction SilentlyContinue)) {
        Fail "Cargo not found. Install Rust from https://rustup.rs and retry."
    }

    $rustVersion = (& cargo --version 2>&1)
    Write-Info "Rust: $rustVersion"

    $tmpDir = Join-Path $env:TEMP "vledger-build-$(New-Guid)"
    New-Item -ItemType Directory -Path $tmpDir -Force | Out-Null

    try {
        Write-Info "Cloning repository at $VersionTag..."
        & git clone --depth 1 --branch $VersionTag "https://github.com/$Repo.git" "$tmpDir\vectorledger" 2>&1 | Select-Object -Last 3 | Write-Host

        Write-Info "Building release binary (this may take several minutes)..."
        Push-Location "$tmpDir\vectorledger"
        try {
            & cargo build --release --package vledger
            if ($LASTEXITCODE -ne 0) { Fail "cargo build failed." }
        } finally {
            Pop-Location
        }

        $builtBinary = Join-Path "$tmpDir\vectorledger\target\release" $Binary
        Install-Binary -Src $builtBinary -Dir $DestDir
    } finally {
        Remove-Item -Recurse -Force $tmpDir -ErrorAction SilentlyContinue
    }
}

# ── Binary installation ────────────────────────────────────────────────────────

function Install-Binary {
    param([string] $Src, [string] $Dir)

    if (-not (Test-Path $Dir)) {
        New-Item -ItemType Directory -Path $Dir -Force | Out-Null
    }

    $dest = Join-Path $Dir $Binary
    Copy-Item -Path $Src -Destination $dest -Force
    Write-Ok "Installed: $dest"
}

# ── Main ───────────────────────────────────────────────────────────────────────

Write-Bold ""
Write-Bold "  VectorLedger Installer for Windows"
Write-Bold "  VectorGuard Labs — https://vectorguardlabs.com"
Write-Bold ""

$arch       = Get-Arch
$version    = Resolve-Version -RequestedVersion $Version
$installDir = Resolve-InstallDir -Dir $InstallDir

Write-Info "Platform      : windows-$arch"
Write-Info "Version       : $version"
Write-Info "Install dir   : $installDir"

# ── Asset names ────────────────────────────────────────────────────────────────
# Expected convention: vledger-<version>-windows-<arch>.zip
$assetName    = "vledger-$version-windows-$arch.zip"
$checksumName = "vledger-$version-checksums.txt"
$assetUrl     = "$ReleasesDownload/$version/$assetName"
$checksumUrl  = "$ReleasesDownload/$version/$checksumName"

$tmpDir = Join-Path $env:TEMP "vledger-install-$(New-Guid)"
New-Item -ItemType Directory -Path $tmpDir -Force | Out-Null

try {
    # ── Download ───────────────────────────────────────────────────────────
    $archivePath  = Join-Path $tmpDir $assetName
    $checksumPath = Join-Path $tmpDir $checksumName

    Write-Info "Downloading $assetName..."
    try {
        Download-File -Url $assetUrl -Dest $archivePath
    } catch {
        Write-Warn "Pre-built binary not available: $_"
        Build-FromSource -VersionTag $version -DestDir $installDir
        if (-not $NoPathUpdate) { Add-ToUserPath -Dir $installDir }

        Write-Bold ""
        Write-Bold "  VectorLedger $version is ready."
        Write-Bold ""
        Write-Bold "  Quick start (PowerShell):"
        Write-Host "    `$env:VectorLedger_MASTER_KEY = (openssl rand -hex 32)"
        Write-Host "    vledger init"
        Write-Host "    vledger start"
        Write-Bold ""
        exit 0
    }

    # ── Verify checksum (best-effort) ──────────────────────────────────────
    Write-Info "Verifying checksum..."
    try {
        Download-File -Url $checksumUrl -Dest $checksumPath
        Verify-Checksum -FilePath $archivePath -ChecksumFile $checksumPath
    } catch {
        Write-Warn "Checksum file not available — skipping verification."
    }

    # ── Extract ────────────────────────────────────────────────────────────
    Write-Info "Extracting archive..."
    Expand-Archive -Path $archivePath -DestinationPath $tmpDir -Force

    $binaryPath = Get-ChildItem -Path $tmpDir -Filter $Binary -Recurse | Select-Object -First 1 -ExpandProperty FullName
    if (-not $binaryPath) {
        Fail "Could not find '$Binary' inside the downloaded archive."
    }

    # ── Install ────────────────────────────────────────────────────────────
    Write-Info "Installing $Binary to $installDir..."
    Install-Binary -Src $binaryPath -Dir $installDir

    # ── Verify ────────────────────────────────────────────────────────────
    $installedBin = Join-Path $installDir $Binary
    $installedVer = (& $installedBin --version 2>&1)
    Write-Ok "Installed: $installedBin  ($installedVer)"

    # ── PATH ───────────────────────────────────────────────────────────────
    if (-not $NoPathUpdate) { Add-ToUserPath -Dir $installDir }

} finally {
    Remove-Item -Recurse -Force $tmpDir -ErrorAction SilentlyContinue
}

Write-Bold ""
Write-Bold "  VectorLedger $version is ready."
Write-Bold ""
Write-Bold "  Quick start (PowerShell):"
Write-Host "    `$env:VectorLedger_MASTER_KEY = (openssl rand -hex 32)"
Write-Host "    vledger init"
Write-Host "    vledger start"
Write-Bold ""
Write-Bold "  Full documentation: https://github.com/$Repo#readme"
Write-Bold ""
