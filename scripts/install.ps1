# Install swain_cli as a single, self-contained binary (no Python required).
#
# Usage (PowerShell):
#   iwr -useb https://raw.githubusercontent.com/takifouhal/swain_cli/HEAD/scripts/install.ps1 | iex
#   # (or, once published as a release asset)
#   # iwr -useb https://github.com/takifouhal/swain_cli/releases/latest/download/install.ps1 | iex
# Optional:
#   $env:VERSION = 'vX.Y.Z'; $env:SWAIN_CLI_INSTALL_REQUIRE_CHECKSUM = '1'; iwr -useb https://raw.githubusercontent.com/takifouhal/swain_cli/HEAD/scripts/install.ps1 | iex

$ErrorActionPreference = 'Stop'

$Repo    = 'takifouhal/swain_cli'
$DefaultVersion = 'latest'
$Version = $env:VERSION
if ([string]::IsNullOrWhiteSpace($Version)) { $Version = $DefaultVersion }
$RequireChecksum = $env:SWAIN_CLI_INSTALL_REQUIRE_CHECKSUM
if ([string]::IsNullOrWhiteSpace($RequireChecksum)) { $RequireChecksum = '0' }

$Arch = $env:PROCESSOR_ARCHITECTURE
switch -Regex ($Arch) {
  'AMD64' { $arch = 'x86_64'; $note = $null }
  'ARM64' { $arch = 'x86_64'; $note = 'ARM64 detected; using x86_64 binary (runs under emulation).'}
  default { throw "Unsupported architecture: $Arch" }
}

$asset = "swain_cli-windows-$arch.exe"
$downloadUrl = "https://github.com/$Repo/releases/download/$Version/$asset"
$tmp = New-TemporaryFile
$tmpPath = $tmp.FullName
$checksumTmp = New-TemporaryFile
$checksumPath = $checksumTmp.FullName

Write-Host "Downloading $asset ..."
$invokeParams = @{
  OutFile = $tmpPath
  MaximumRedirection = 5
  ErrorAction = 'Stop'
}
if ($PSVersionTable.PSVersion.Major -lt 6) { $invokeParams.UseBasicParsing = $true }

try {
  Invoke-WebRequest -Uri $downloadUrl @invokeParams
} catch {
  if ($Version -eq 'latest') {
    $fallback = "https://github.com/$Repo/releases/latest/download/$asset"
    Write-Host "Retrying with latest release asset..."
    Invoke-WebRequest -Uri $fallback @invokeParams
    $downloadUrl = $fallback
  } else {
    throw
  }
}

$checksumUrl = "$downloadUrl.sha256"
$checksumAvailable = $false
try {
  $checksumInvokeParams = $invokeParams.Clone()
  $checksumInvokeParams.OutFile = $checksumPath
  Invoke-WebRequest -Uri $checksumUrl @checksumInvokeParams | Out-Null
  $checksumAvailable = $true
} catch {
  if ($RequireChecksum -in @('1', 'true', 'True', 'TRUE')) { throw }
  Write-Warning "Checksum file not found; skipping verification ($checksumUrl)"
}

if ($checksumAvailable) {
  $checksumText = Get-Content -Path $checksumPath -Raw
  if ($checksumText -match '([0-9a-fA-F]{64})') {
    $expected = $Matches[1].ToLower()
  } else {
    throw "Checksum file did not contain a SHA-256 value: $checksumUrl"
  }
  $actual = (Get-FileHash -Path $tmpPath -Algorithm SHA256).Hash.ToLower()
  if ($expected -ne $actual) {
    throw "Checksum mismatch for $asset; expected $expected, got $actual"
  }
  Write-Host "Checksum verified ($expected)"
}

$installDir = "$env:LOCALAPPDATA\Programs\swain_cli"
New-Item -ItemType Directory -Force -Path $installDir | Out-Null
$target = Join-Path $installDir 'swain_cli.exe'
Move-Item -Force $tmpPath $target

Write-Host "Installed $target"
if ($note) { Write-Warning $note }

# Ensure installDir on PATH for current session; suggest persistence
if (-not ($env:PATH -split ';' | Where-Object { $_ -eq $installDir })) {
  Write-Warning "$installDir is not on your PATH."
  Write-Host "Add it permanently via: [Environment]::SetEnvironmentVariable('Path', \"$env:Path;$installDir\", 'User')" -ForegroundColor Yellow
  $env:PATH = "$env:PATH;$installDir"
}

Write-Host 'Done. Run: swain_cli --help'
