Function Start-iTripwireTask
{
param (
    $websession,
    [string]$systemname  = "tripwire-prod.company.com",      # Use the Tripwire server name.
    [string]$taskID      = "-1y2p0ij32e7ja:-1y2p0iivvz5ve", #Report Automation
    [int]$pagelimit      = 100,
    [string]$isdisabled  = "false",
    [string]$auditenabled= "true"
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

$body                     = '{ "requestData": { "taskId":"' + $taskID + '" } }'
$uri                      = "https://$systemname/api/v1/tasks/executeTaskRequests"

$starttask                = Invoke-RestMethod -uri $uri -Method Post -Body $body -WebSession $websession
return $starttask

}
