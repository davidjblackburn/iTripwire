Function Get-iTripwireUnknownPolicyTestResults
{
param (
            $websession,
    [string]$policyId        = "-1y2p0ij32e886:-1y2p0ij32bzxz",  # Use a policyId for testing.
    [string]$systemname      = "tripwire-prod.company.com"      # Use the Tripwire server name.
    )

$info                 = "" | Select-Object is_over_14_days_old, last_passed_days_old

# Collect unknown policy test results
$uri                      = "https://$systemname/api/v1/policytestresults/unknownTestResults"
$results                  = Invoke-RestMethod -uri $uri -Method get -WebSession $websession

[void][System.Reflection.Assembly]::LoadWithPartialName("System.Web.Extensions")        
$jsonserial               = New-Object -TypeName System.Web.Script.Serialization.JavaScriptSerializer 
$jsonserial.MaxJsonLength = 67108864
$resultsjson              = $jsonserial.DeserializeObject($results)
$resultsjsonpolicyid      = $resultsjson | Where-Object {$_.policyId -eq $policyId}

$results                  = $null
$resultsjson              = $null

$results_final            = @()
foreach ($ra in $resultsjsonpolicyid)
{
    $res                      = $null
    $res                      = "" | Select-Object policyId, nodeId, policyTestId
    $res.policyId             = $ra.policyId
    $res.nodeId               = $ra.nodeId
    $res.policyTestId         = $ra.policyTestId
    $results_final           += $res
}

$results_final

}
