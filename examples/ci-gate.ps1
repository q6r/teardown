# CI gate for PowerShell: analyse a build artefact and fail when teardown finds something serious.
#
#   .\examples\ci-gate.ps1 build\app.exe            # fail on high or critical (default)
#   .\examples\ci-gate.ps1 build\app.apk medium     # stricter
#
# Exit status: 0 clean, 3 threshold reached (teardown's own code), anything else is an error.
param(
    [Parameter(Mandatory = $true, Position = 0)][string]$Artefact,
    [Parameter(Position = 1)][ValidateSet('info', 'low', 'medium', 'high', 'critical')][string]$Severity = 'high',
    [string]$Report = 'teardown-report.md'
)

teardown analyze $Artefact --md --output $Report --fail-on $Severity
$status = $LASTEXITCODE

switch ($status) {
    0 { Write-Host "teardown: no finding at or above '$Severity' in $Artefact" }
    3 { Write-Error "teardown: '$Severity' threshold reached, see $Report" }
    default { Write-Error "teardown: analysis failed with status $status" }
}
exit $status
