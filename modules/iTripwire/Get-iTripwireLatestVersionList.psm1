Function Get-iTripwireLatestVersionList
{
param (
    $websession,
    [string]$exists      = "True",
    [string]$nodeId      = "-1y2p0ij39e2bv:-1y2p0ij29b9jb",  # Use a nodeId for testing.   
    [array]$ruleId       = $null,
    [string]$systemname  = "tripwire-prod.company.com",     # Use the Tripwire server name.
    [int]$pagelimit      = 100,
    [int]$pagestart      = 0
    )

$headerplaintext             = @{"Accept"="text/plain"}
$headerappjson               = @{"Accept"="application/json"}

add-type @"
    using System.Net;
    using System.Security.Cryptography.X509Certificates;
    public class TrustAllCertsPolicy : ICertificatePolicy {
        public bool CheckValidationResult(
            ServicePoint srvPoint, X509Certificate certificate,
            WebRequest request, int certificateProblem) {
            return true;
        }
    }
"@
[System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$ruleslist                 = $null
$has_ruleid                = $false
$has_nodeid                = $false

#if (($ruleId -eq $null) -or ($ruleId -match $null))
if ($ruleId -eq $null)
{
    $has_ruleid                = $false
}
else
{
    $has_ruleid                = $true
}

if ($has_ruleid                = $true)
{
    foreach($rule in $ruleId)
    {
        $ruleId_list += "&ruleId=$rule"
    }
    $uri                       = "https://$systemname/api/v1/versions/latest?pageLimit=$pagelimit&exists=$exists&nodeId=$nodeId" + $ruleId_list
}
else
{
    $uri                       = "https://$systemname/api/v1/versions/latest?pageLimit=$pagelimit&exists=$exists&nodeId=$nodeId"
}


$latestversions            = Invoke-RestMethod -uri $uri -Method get -WebSession $websession -Headers $headerappjson
$latestversionlist         = $latestversions
do
{
        $pagestart        += $pagelimit
        if ($has_ruleid    = $true)
        {
            foreach($rule in $ruleId)
            {
                $ruleId_list += "&ruleId=$rule"
            }
            $uri                       = "https://$systemname/api/v1/versions/latest?pageLimit=$pagelimit&exists=$exists&nodeId=$nodeId" + $ruleId_list
        }
        else
        {
            $uri                       = "https://$systemname/api/v1/versions/latest?pageLimit=$pagelimit&exists=$exists&nodeId=$nodeId"
        }

        $latestversions    = Invoke-RestMethod -uri $uri -Method get -WebSession $websession
        $latestversionlist+= $latestversions

} while ($latestversions.count -eq $pagelimit)


return $latestversionlist

}
