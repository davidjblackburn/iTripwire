Function Get-iTripwireWaiver
{
param (
    $websession,
    [string]$policyId,
    [string]$policyTestId,
    [string]$nodeId,
    [string]$systemname               = "tripwire-prod.company.com"           # Use the Tripwire server name.
    )

$headerplaintext             = @{"Accept"="text/plain"}
$headerappjson               = @{"Accept"="application/json"}
$results                     = $null

# Get complete list of waivers
$waiverlist                  = Get-iTripwirePolicyTestWaivers -websession $websession

# Find PolicyId for test to check for waiver
$policyresults               = $waiverlist | Where-Object { $_.policyId -eq $policyId }

if ($policyresults.count -gt 0 -or $policyresults.id.Length -gt 0 )
{
    $results                     = $policyresults | Where-Object { $_.waivedTests.nodeid -eq $nodeId -and $_.waivedTests.policytestid -eq $policyTestId } | Sort-Object -Property expiration -Descending | Select-Object -First 1
}

$results

}
