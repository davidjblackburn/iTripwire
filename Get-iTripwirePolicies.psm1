Function Get-iTripwirePolicies
{
param (
    [string]$server          = "tripwire-prod.company.com", # Use the Tripwire server name.
    [string]$policyname      = "",
            $websession,
    [int]   $pagelimit       = 100,
    [int]   $pagestart       = 0
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

$headerplaintext = @{"Accept"="text/plain"}
$headerappjson   = @{"Accept"="application/json"}

$uri           = "https://$server/api/v1/policies?pageLimit=$pagelimit&pageStart=$pagestart"

# Get list of Tripwire policies
$results       = Invoke-RestMethod -uri $uri -Method get -WebSession $websession -Headers $headerappjson
$policylist    = $results
$pagestart_t   = $pagestart

if ($results.count -eq $pagelimit)
{
    do
    {
            $pagestart_t       += $pagelimit
            $uri                = "https://$server/api/v1/policies?pageLimit=$pagelimit&pageStart=$pagestart_t"
            $results            = Invoke-RestMethod -uri $uri -Method get -WebSession $websession
            $policylist        += $results

    } while ($results.count -eq $pagelimit)
}

if ($policyname -eq "") 
{

    # Get list of all Tripwire policies
    $policies         = $policylist

}
else
{

    # Get list of Tripwire policies matching '$policyname'
    $policies         = $policylist | Where-Object {$_.name -match $policyname}
}

$policies

}
