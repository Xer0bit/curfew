# Installs Curfew on Windows. Run from an elevated (Administrator) PowerShell:
#   irm https://raw.githubusercontent.com/Xer0bit/curfew/master/setup.ps1 | iex
#
# There's no prebuilt Windows binary yet, so this builds from source. It also
# checks for the two drivers Curfew needs on Windows (Npcap and WinDivert) —
# it can't fully automate those (they show their own installer/consent UI),
# but it gets you as close as possible and tells you exactly what's left.

$ErrorActionPreference = "Stop"
$Repo = "Xer0bit/curfew"
$InstallDir = "C:\ProgramData\Curfew"

function Info($msg) { Write-Host $msg -ForegroundColor Cyan }
function Ok($msg)   { Write-Host $msg -ForegroundColor Green }
function Warn($msg) { Write-Host $msg -ForegroundColor Yellow }
function Fail($msg) { Write-Host $msg -ForegroundColor Red; exit 1 }

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Fail "Run this from an elevated PowerShell (Run as Administrator)."
}

Write-Host "Curfew - give your household's network a bedtime." -ForegroundColor Cyan
Write-Host ""

# --- Rust toolchain ---
if (-not (Get-Command cargo -ErrorAction SilentlyContinue)) {
    Info "Installing Rust via rustup..."
    $rustupExe = "$env:TEMP\rustup-init.exe"
    Invoke-WebRequest -Uri "https://win.rustup.rs/x86_64" -OutFile $rustupExe
    & $rustupExe -y
    $env:Path = "$env:USERPROFILE\.cargo\bin;$env:Path"
}

# --- Npcap (needed for ARP spoofing via pnet) ---
$npcapInstalled = Test-Path "$env:SystemRoot\System32\Npcap"
if (-not $npcapInstalled) {
    Warn "Npcap isn't installed. It's required for Curfew to redirect device traffic."
    Warn "Download it (check 'Install Npcap in WinPcap API-compatible Mode'): https://npcap.com/#download"
    Warn "Re-run this script after installing it."
    Fail "Stopping here until Npcap is installed."
}
Ok "Npcap found."

# --- WinDivert (needed for traffic shaping) ---
if (-not $env:WINDIVERT_PATH) {
    Warn "WINDIVERT_PATH isn't set. Download the WinDivert SDK zip from https://reqrypt.org/windivert.html,"
    Warn "extract it, and set WINDIVERT_PATH to that folder, e.g.:"
    Warn '  [Environment]::SetEnvironmentVariable("WINDIVERT_PATH", "C:\WinDivert-2.2.2-A", "User")'
    Warn "Re-run this script (in a new PowerShell window, so the variable is picked up) after that."
    Fail "Stopping here until WINDIVERT_PATH is set."
}
Ok "WINDIVERT_PATH set to $env:WINDIVERT_PATH."

# --- Build from source ---
if (-not (Get-Command git -ErrorAction SilentlyContinue)) {
    Fail "Git is required. Install it from https://git-scm.com/download/win and re-run."
}

$src = Join-Path $env:TEMP "curfew-src"
if (Test-Path $src) { Remove-Item -Recurse -Force $src }
Info "Cloning and building from source (this takes a minute)..."
git clone --depth 1 "https://github.com/$Repo" $src
Push-Location $src
cargo build --release
Pop-Location

New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
Copy-Item "$src\target\release\curfew.exe" "$InstallDir\curfew.exe" -Force

# Copy the WinDivert runtime DLL/driver next to the binary — needed at
# runtime, not just build time.
$driverFiles = @("WinDivert.dll", "WinDivert64.sys", "WinDivert32.sys")
foreach ($f in $driverFiles) {
    $p = Join-Path $env:WINDIVERT_PATH "x64\$f"
    if (Test-Path $p) { Copy-Item $p $InstallDir -Force }
}

Ok "Installed to $InstallDir\curfew.exe"
Write-Host ""
Write-Host "Run it (as Administrator) with:" -NoNewline
Write-Host " $InstallDir\curfew.exe" -ForegroundColor Cyan
