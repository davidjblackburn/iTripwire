Function Get-iTripwireElementsListNodeandRule
{
param (
    $websession,
    [string]$ruleid      = "-1y2p0lj36e7m7:-1y2p0ij42wmy7",  # Use a ruleId for testing.
    [string]$nodeid      = "-1y2p0ij39e2bv:-1y2p0ij29b9jb",  # Use a nodeId for testing.
    [string]$systemname  = "tripwire-prod.company.com",
    [int]$pagelimit      = 100
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

$elementslist             = @()

$uri                      = "https://$systemname/api/v1/elements?nodeId=$nodeid&ruleId=$ruleid&pageLimit=$pageLimit"

$elements                 = Invoke-RestMethod -uri $uri -Method get -WebSession $websession -Headers $headerappjson
$elementslist            += $elements
$elementscount            = $elements.count
do 
{
    $previousId               = $elements[$pageLimit-1].id
    $uri                      = "https://$systemname/api/v1/elements?nodeId=$nodeid&ruleId=$ruleid&pageLimit=$pageLimit&previousId=$previousId"
    $elements                 = Invoke-RestMethod -uri $uri -Method get -WebSession $websession -Headers $headerappjson
    $elementscount            = $elements.count
    $elementslist            += $elements
}
while ($elementscount -eq $pagelimit)

return $elementslist

}
