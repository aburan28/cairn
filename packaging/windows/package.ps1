param(
    [Parameter(Mandatory=$true)][string]$Binary,
    [Parameter(Mandatory=$true)][string]$Version,
    [string]$Target = 'x86_64-pc-windows-msvc',
    [string]$OutputDirectory = '.'
)
$ErrorActionPreference = 'Stop'
if ($Version -notmatch '^[A-Za-z0-9._-]+$' -or $Target -notmatch '^[A-Za-z0-9._-]+$') { throw 'Unsafe package name' }
if (-not (Test-Path -LiteralPath $Binary -PathType Leaf)) { throw 'Windows binary is missing' }
$repo = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
$out = New-Item -ItemType Directory -Force -Path $OutputDirectory
$stage = Join-Path $out.FullName ('stage-' + [Guid]::NewGuid())
New-Item -ItemType Directory -Path $stage | Out-Null
try {
    Copy-Item -LiteralPath $Binary -Destination (Join-Path $stage 'cairn.exe')
    $launcher = [IO.File]::ReadAllText((Join-Path $PSScriptRoot 'Start Cairn.cmd')) -replace '\r?\n', "`r`n"
    [IO.File]::WriteAllText((Join-Path $stage 'Start Cairn.cmd'), $launcher, [Text.Encoding]::ASCII)
    Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'README.txt') -Destination $stage
    Copy-Item -LiteralPath (Join-Path $repo 'LICENSE') -Destination $stage
    $name = "cairn-$Version-$Target.zip"
    $zip = Join-Path $out.FullName $name
    Compress-Archive -Path (Join-Path $stage '*') -DestinationPath $zip -Force
    $hash = (Get-FileHash -LiteralPath $zip -Algorithm SHA256).Hash.ToLowerInvariant()
    Set-Content -LiteralPath "$zip.sha256" -Value "$hash  $name" -Encoding ascii
    Write-Output $zip
} finally {
    Remove-Item -LiteralPath $stage -Recurse -Force
}
