Function Get-iTripwireVersionElementContent
{
param (
    $websession,
    [string]$elementid   = "-1y2p0ij32e8ch:-1y2p0iixjime6",      # Use a elemendId for testing.
    [string]$systemname  = "tripwire-prod.company.com"           # Use the Tripwire server name.

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


$uri                      = "https://$systemname/api/v1/versions/$elementid/content"
$content                  = Invoke-RestMethod -uri $uri -Method get -WebSession $websession -Headers $headerplaintext

return $content

}
