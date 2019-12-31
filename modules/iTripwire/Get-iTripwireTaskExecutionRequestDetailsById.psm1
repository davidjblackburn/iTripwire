Function Get-iTripwireTaskExecutionRequestDetailsById
{
param (
    $websession,
    [string]$systemname      = "tripwire-prod.company.com",      # Use the Tripwire server name.
    [string]$requestId       = "1360302"                         #   
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

$uri                      = "https://$systemname/api/v1/tasks/executeTaskRequests/$requestId"
$results                  = Invoke-RestMethod -uri $uri -Method get -WebSession $websession

return $results

}
