Function Get-iTripwireVersionList
{
param (
    $websession,
    [string]$exists      = "True",
    [string]$nodeId      = "-1y2p0ij32e8bv:-1y2p0ij32e7c4",    # Use a nodeId for testing.
    [string]$ruleId      = "-1y2p0ij32e8b6:-1y2p0ij31ssp3",    # Use a ruleId for testing.
    [string]$systemname  = "tripwire-prod.company.com",        # Use the Tripwire server name.
    [int]$pagelimit      = 100,
    [int]$pagestart      = 0
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

$uri                       = "https://$systemname/api/v1/versions?exists=true&pageLimit=$pagelimit&nodeId=$nodeId&ruleId=$ruleid"

$versions                  = Invoke-RestMethod -uri $uri -Method get -WebSession $websession
$versionslist              = $versions
do
{
        $pagestart        += $pagelimit
        $uri               = "https://$systemname/api/v1/versions?exists=true&pageLimit=$pagelimit&pageStart=$pagestart&nodeId=$nodeId&ruleId=$ruleid"
        $versions          = Invoke-RestMethod -uri $uri -Method get -WebSession $websession
        $versionslist      += $versions

} while ($versions.count -eq $pagelimit)

return $versionslist

}
