# Install swain_cli as a single, self-contained binary (no Python required).
#
# Usage (PowerShell):
#   iwr -useb https://raw.githubusercontent.com/takifouhal/swain_cli/HEAD/scripts/install.ps1 | iex
# Optional:
#   $env:VERSION = 'v0.3.2'; iwr -useb https://raw.githubusercontent.com/takifouhal/swain_cli/HEAD/scripts/install.ps1 | iex

$ErrorActionPreference = 'Stop'

$Repo    = 'takifouhal/swain_cli'
$Version = $env:VERSION
if ([string]::IsNullOrWhiteSpace($Version)) { $Version = 'latest' }

$Arch = $env:PROCESSOR_ARCHITECTURE
switch -Regex ($Arch) {
  'AMD64' { $arch = 'x86_64'; $note = $null }
  'ARM64' { $arch = 'x86_64'; $note = 'ARM64 detected; using x86_64 binary (runs under emulation).'}
  default { throw "Unsupported architecture: $Arch" }
}

$asset = "swain_cli-windows-$arch.exe"
$baseUrl = "https://github.com/$Repo/releases/download/$Version/$asset"
$tmp = New-TemporaryFile

Write-Host "Downloading $asset ..."
try {
  Invoke-WebRequest -Uri $baseUrl -OutFile $tmp -UseBasicParsing -MaximumRedirection 5 -ErrorAction Stop
} catch {
  if ($Version -eq 'latest') {
    $fallback = "https://github.com/$Repo/releases/latest/download/$asset"
    Write-Host "Retrying with latest release asset..."
    Invoke-WebRequest -Uri $fallback -OutFile $tmp -UseBasicParsing -MaximumRedirection 5 -ErrorAction Stop
  } else {
    throw
  }
}

$installDir = "$env:LOCALAPPDATA\Programs\swain_cli"
New-Item -ItemType Directory -Force -Path $installDir | Out-Null
$target = Join-Path $installDir 'swain_cli.exe'
Move-Item -Force $tmp $target

Write-Host "Installed $target"
if ($note) { Write-Warning $note }

# Ensure installDir on PATH for current session; suggest persistence
if (-not ($env:PATH -split ';' | Where-Object { $_ -eq $installDir })) {
  Write-Warning "$installDir is not on your PATH."
  Write-Host "Add it permanently via: [Environment]::SetEnvironmentVariable('Path', \"$env:Path;$installDir\", 'User')" -ForegroundColor Yellow
  $env:PATH = "$env:PATH;$installDir"
}

Write-Host 'Done. Run: swain_cli --help'
