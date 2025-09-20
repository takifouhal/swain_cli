param(
    [Parameter(Mandatory=$true)][string]$JdkZip,
    [Parameter(Mandatory=$true)][string]$OutputZip
)

$work = Join-Path ([System.IO.Path]::GetTempPath()) ([System.Guid]::NewGuid().ToString())
New-Item -ItemType Directory -Path $work | Out-Null
try {
    $src = Join-Path $work 'src'
    $out = Join-Path $work 'out'
    New-Item -ItemType Directory -Path $src,$out | Out-Null

    Expand-Archive -Path $JdkZip -DestinationPath $src -Force
    $jdkDir = Get-ChildItem -Path $src -Directory | Where-Object { $_.Name -like 'jdk-*' } | Select-Object -First 1
    if (-not $jdkDir) {
        throw 'Could not locate extracted JDK directory'
    }

    $jlink = Join-Path $jdkDir.FullName 'bin\jlink.exe'
    & $jlink `
        --compress=2 `
        --no-header-files `
        --no-man-pages `
        --strip-debug `
        --add-modules java.se,jdk.httpserver,jdk.unsupported `
        --output (Join-Path $out 'jre')

    if (Test-Path $OutputZip) {
        Remove-Item -Path $OutputZip -Force
    }
    Compress-Archive -Path (Join-Path $out 'jre') -DestinationPath $OutputZip -CompressionLevel Optimal
    Get-FileHash -Algorithm SHA256 -Path $OutputZip
}
finally {
    Remove-Item -Recurse -Force -Path $work
}
