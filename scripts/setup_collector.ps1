# setup_collector.ps1
# This script automates the download and setup of Npcap and Python dependencies for the KodiakAiOps Collector.

$ErrorActionPreference = "Stop"

function Write-Host-Color {
    param([string]$Message, [string]$Color = "Cyan")
    Write-Host "`n[#] $Message" -ForegroundColor $Color
}

# 1. Check for Administrative Privileges
Write-Host-Color "Checking for Administrative privileges..."
$currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host-Color "ERROR: This script MUST be run as Administrator." "Red"
    Write-Host "Please right-click PowerShell and select 'Run as Administrator'."
    exit 1
}

# 2. Define Npcap Download Details
$npcUrl = "https://npcap.com/dist/npcap-1.85.exe"
$npcPath = Join-Path $env:TEMP "npcap-setup.exe"

# 3. Download Npcap
Write-Host-Color "Downloading Npcap Installer (v1.85)..."
try {
    Invoke-WebRequest -Uri $npcUrl -OutFile $npcPath
    Write-Host "Download complete: $npcPath"
} catch {
    Write-Host-Color "ERROR: Failed to download Npcap. Please check your internet connection." "Red"
    exit 1
}

# 4. Install Python Dependencies
Write-Host-Color "Installing Python dependencies..."
$reqFile = Join-Path $PSScriptRoot "requirements_collector.txt"
if (Test-Path $reqFile) {
    pip install -r $reqFile
} else {
    Write-Host "Warning: $reqFile not found. Skipping pip install." -ForegroundColor Yellow
}

# 5. Launch Npcap Installer
Write-Host-Color "Launching Npcap Installer..." "Green"
Write-Host "IMPORTANT: Please check the box 'Install Npcap in WinPcap API-compatible Mode' during installation." -ForegroundColor Yellow
Start-Process -FilePath $npcPath -Wait

Write-Host-Color "Setup process finished. You can now run the collector." "Green"
Write-Host "Path: .\dist\KodiakAiOps-Collector.exe"
