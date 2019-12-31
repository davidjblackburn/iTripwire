Function Get-iTripwirePolicyTests
{
param (
    [string]$systemname      = "tripwire-prod.company.com",      # Use the Tripwire server name.
    [string]$policyId        = "",
            $websession,
    [int]   $pagelimit       = 100,
    [int]   $pagestart       = 0
)

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

$uri           = "https://$systemname/api/v1/policytests?policyId=$policyId&pageLimit=$pagelimit&pageStart=$pagestart"

# Get list of Tripwire policies
$results       = Invoke-RestMethod -uri $uri -Method get -WebSession $websession
$policytests   = $results
$pagestart_t   = $pagestart

if ($results.count -eq $pagelimit)
{
    do
    {
            $pagestart_t       += $pagelimit
            $uri                = "https://$systemname/api/v1/policytests?policyId=$policyId&pageLimit=$pagelimit&pageStart=$pagestart_t"
            $results            = Invoke-RestMethod -uri $uri -Method get -WebSession $websession
            $policytests       += $results

    } while ($results.count -eq $pagelimit)
}

$policytests

}
