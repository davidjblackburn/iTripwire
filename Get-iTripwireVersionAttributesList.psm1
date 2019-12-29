Function Get-iTripwireVersionAttributesList
{
param (
    $websession,
    [string]$versionid   = "-1y2p0ij32e8ch%3A-1y2p0ij32ci5a",  # Use a versionId for testing.
    [string]$systemname  = "tripwire-prod.company.com",        # Use the Tripwire server name.
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

$versionattributes         = $null

$uri                       = "https://$systemname/api/v1/versions/$versionid/attributes"

$versionattributes         = Invoke-RestMethod -uri $uri -Method get -WebSession $websession

return $versionattributes

}
