# Upload every file of examples\samples (and any extra files you pass) to a running
# `teardown serve` through the real HTTP API, so the dashboard has something to show.
#
#   teardown serve                                      # in another terminal
#   .\examples\upload-samples.ps1                       # the committed samples
#   .\examples\upload-samples.ps1 -BaseUrl http://127.0.0.1:9000
#   .\examples\upload-samples.ps1 -Extra dropper.bin    # plus your own files
#
# Prints one line per file: analysis id, risk, name. Uses curl.exe, which ships with Windows 10+.
param(
    [string]$BaseUrl = 'http://127.0.0.1:7777',
    [string[]]$Extra = @()
)

$samples = Join-Path $PSScriptRoot 'samples'
$files = @(Get-ChildItem -LiteralPath $samples -File) + @($Extra | ForEach-Object { Get-Item -LiteralPath $_ })

$failed = $false
foreach ($file in $files) {
    $json = curl.exe -sS -F "file=@$($file.FullName)" "$BaseUrl/api/analyze"
    if ($LASTEXITCODE -ne 0) { Write-Error "curl failed for $($file.Name)"; $failed = $true; continue }
    $answer = $json | ConvertFrom-Json
    if ($answer.error) {
        Write-Error "$($file.Name): $($answer.error.code): $($answer.error.message)"
        $failed = $true
        continue
    }
    '{0}  risk {1,3} {2,-8} {3}' -f $answer.id, $answer.report.risk.score, $answer.report.risk.label, $file.Name
}
if ($failed) { exit 1 }
