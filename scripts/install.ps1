# Install cairn on Windows, inside WSL 2.
#
#   irm https://github.com/aburan28/cairn/releases/latest/download/install.ps1 | iex
#
# There is no native Windows build, on purpose: the verifier jail is seatbelt
# and bubblewrap, and a node that runs objective-authored code without one is
# the configuration CAIRN_REQUIRE_SANDBOX exists to refuse (docs/install.md).
# WSL 2 is a real Linux kernel, so the Linux release runs there unchanged, with
# its jail. This script finds (or offers to install) a WSL 2 distribution, runs
# the Linux install.sh inside it, installs bubblewrap as root so there is no
# sudo prompt, and says how to start a node. The reader is then an ordinary
# browser tab at http://127.0.0.1:8080/ui/ on Windows.
#
# Settings, as environment variables:
#   CAIRN_VERSION      release tag to install (default: latest)
#   CAIRN_WSL_DISTRO   WSL distribution to use (default: your default, if WSL 2)
#   CAIRN_START=no     install only; do not offer to start a node
#
# Like install.sh, this checks nothing about who served it. Once installed, the
# check that means something is `cairn --log launch/cairn.jsonl --root . audit`.
& {
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$installer = 'https://github.com/aburan28/cairn/releases/latest/download/install.sh'

function Say([string]$Text) { Write-Host "==> $Text" -ForegroundColor Cyan }
function Stop-Here([string]$Text) { Write-Host $Text -ForegroundColor Yellow; return }

# Version feeds a shell command line inside the distribution, so allow only what
# a release tag can contain.
$version = $env:CAIRN_VERSION
if ($version -and $version -notmatch '^v?[0-9A-Za-z][0-9A-Za-z.+-]*$') {
    throw "CAIRN_VERSION '$version' is not a release tag such as v12.1.0"
}

if ([Environment]::OSVersion.Version.Build -lt 19041) {
    Stop-Here 'WSL 2 needs Windows 10 version 2004 (build 19041) or newer, or Windows 11.'
    return
}

# `wsl -l -v` prints UTF-16. Read it as that, and put the console back after.
function Get-Distros {
    $previous = [Console]::OutputEncoding
    try {
        [Console]::OutputEncoding = [Text.Encoding]::Unicode
        $lines = & wsl.exe -l -v 2>$null
        if ($LASTEXITCODE -ne 0) { return @() }
    } catch { return @() } finally { [Console]::OutputEncoding = $previous }
    foreach ($line in ($lines | Select-Object -Skip 1)) {
        $text = ("$line" -replace "`0", '').Trim()
        if (-not $text) { continue }
        $default = $text.StartsWith('*')
        $parts = ($text.TrimStart('*').Trim()) -split '\s+'
        if ($parts.Count -lt 3) { continue }
        [pscustomobject]@{ Name = $parts[0]; Version = $parts[-1]; Default = $default }
    }
}

$distros = @(Get-Distros | Where-Object { $_.Name -notmatch '^docker-desktop' })
$chosen = $null
if ($env:CAIRN_WSL_DISTRO) {
    $chosen = $distros | Where-Object Name -eq $env:CAIRN_WSL_DISTRO | Select-Object -First 1
    if (-not $chosen) { throw "no WSL distribution named '$($env:CAIRN_WSL_DISTRO)' (see: wsl -l -v)" }
} else {
    $chosen = @($distros | Where-Object { $_.Version -eq '2' } | Sort-Object { -[int]$_.Default })[0]
}

if (-not $chosen) {
    $admin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)
    if ($distros) {
        Stop-Here ("Your WSL distributions are WSL 1: $(($distros).Name -join ', '). Convert one with:`n" +
                   "  wsl --set-version $($distros[0].Name) 2`nthen run this command again.")
        return
    }
    if (-not $admin) {
        Stop-Here ("WSL has no Linux distribution yet. In an Administrator PowerShell run:`n" +
                   "  wsl --install -d Ubuntu`nrestart if it asks, finish Ubuntu's first-run setup (a username), " +
                   "then run this command again.")
        return
    }
    $answer = Read-Host 'WSL has no Linux distribution. Install Ubuntu now? [Y/n]'
    if ($answer -match '^[nN]') { return }
    & wsl.exe --install -d Ubuntu
    Stop-Here ("Ubuntu is installing. Restart Windows if it asks, finish Ubuntu's first-run setup " +
               "(a username), then run this command again.")
    return
}
$distro = $chosen.Name
if ($chosen.Version -ne '2') {
    Stop-Here "$distro is WSL 1, which cannot create the namespaces bubblewrap needs. Run: wsl --set-version $distro 2"
    return
}
Say "using WSL 2 distribution $distro"

# Run a command in the distribution, as the default user or as root. --cd ~ so
# that a node started here keeps its state in the Linux home directory and not
# under /mnt/c, where file locking and permissions do not behave.
function Invoke-Wsl([string]$Command, [switch]$Root) {
    $arguments = @('-d', $distro, '--cd', '~')
    if ($Root) { $arguments += @('-u', 'root') }
    # Out-Host: a function's return value is everything it writes to the
    # pipeline, so without it the exit code would arrive mixed with the output.
    & wsl.exe @arguments -- sh -c $Command | Out-Host
    return $LASTEXITCODE
}

function Add-Package([string]$Name, [string]$Probe) {
    if ((Invoke-Wsl "command -v $Probe >/dev/null 2>&1") -eq 0) { return $true }
    if ((Invoke-Wsl 'command -v apt-get >/dev/null 2>&1') -ne 0) { return $false }
    Say "installing $Name in $distro"
    $code = Invoke-Wsl "apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq $Name" -Root
    return $code -eq 0
}

if (-not (Add-Package 'curl' 'curl')) {
    throw "$distro has no curl and I could not install it; install curl there, then run this again"
}

Say 'installing cairn (the Linux release) into ~/.local/bin'
$pin = if ($version) { "CAIRN_VERSION='$version' " } else { '' }
if ((Invoke-Wsl "curl -fsSL '$installer' | ${pin}sh") -ne 0) {
    throw "the install inside $distro failed; the output above says why"
}

$jailed = (Add-Package 'bubblewrap' 'bwrap') -and ((Invoke-Wsl 'bwrap --ro-bind / / true >/dev/null 2>&1') -eq 0)
if ($jailed) {
    Say 'verifier jail (bubblewrap) works'
} else {
    Write-Host ("Warning: bubblewrap is missing or cannot create a jail in $distro. With CAIRN_REQUIRE_SANDBOX=1 " +
                "(below) a node will answer 'unavailable' for objective code rather than run it unconfined.") -ForegroundColor Yellow
}
Invoke-Wsl '"$HOME/.local/bin/cairn" --version' | Out-Null

$start = "wsl -d $distro --cd ~ -- env CAIRN_REQUIRE_SANDBOX=1 .local/bin/cairn run"
Write-Host @"

Installed in $distro. Start a node any time from PowerShell or cmd with:
  $start
then open http://127.0.0.1:8080/ui/ in your browser. Stop it with Ctrl-C.
The node's state lives in $distro under ~/.local (open it from Windows at \\wsl.localhost\$distro\home).
To remove cairn: wsl -d $distro -- rm ~/.local/bin/cairn
"@

if ($env:CAIRN_START -eq 'no') { return }
$answer = Read-Host 'Start a node now? [Y/n]'
if ($answer -match '^[nN]') { return }
$null = Start-Job {
    for ($i = 0; $i -lt 60; $i++) {
        try { Invoke-WebRequest -UseBasicParsing 'http://127.0.0.1:8080/ui/' -TimeoutSec 2 | Out-Null; Start-Process 'http://127.0.0.1:8080/ui/'; return }
        catch { Start-Sleep -Seconds 1 }
    }
}
Say 'starting the node; your browser opens when it answers (Ctrl-C stops it)'
& wsl.exe -d $distro --cd '~' -- env CAIRN_REQUIRE_SANDBOX=1 .local/bin/cairn run
}
