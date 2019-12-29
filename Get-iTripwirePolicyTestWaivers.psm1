Function Get-iTripwirePolicyTestWaivers
{
param (
    [string]$systemname      = "tripwire-prod.company.com",      # Use the Tripwire server name.
            $websession,
    [int]   $pagelimit       = 100,
    [int]   $pagestart       = 0
)

$headerplaintext          = @{"Accept"="text/plain"}
$headerappjson            = @{"Accept"="application/json"}

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

# Get list of Tripwire waivers
$pagestart_t   = $pagestart
$uri           = "https://$systemname/api/v1/waivers?closed=false&pageLimit=$pagelimit&pageStart=$pagestart_t"

$results       = Invoke-RestMethod -uri $uri -Method get -WebSession $websession -Headers $headerappjson <# Try catch needed #>
$waiverlist    = $results

if ($results.count -eq $pagelimit)
{
    do
    {
            $pagestart_t       += $pagelimit
            $uri                = "https://$systemname/api/v1/waivers?closed=false&pageLimit=$pagelimit&pageStart=$pagestart_t"
            $results            = Invoke-RestMethod -uri $uri -Method get -WebSession $websession -Headers $headerappjson
            $waiverlist        += $results

    } while ($results.count -eq $pagelimit)
}

$results

}
