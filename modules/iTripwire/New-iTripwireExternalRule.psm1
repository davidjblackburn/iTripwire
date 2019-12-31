Function New-iTripwireExternalRule
{
param (
    $websession,
    [string]$systemname     = "tripwire-prod.company.com",        # Use the Tripwire server name.
    [string]$rulename       = "rule",
    [string]$ruledescription= "New rule"
    )
$headerplaintext             = @{"Accept"="text/plain"}
$headerappjson               = @{"Accept"="application/json";"Content-Type"="application/json"}

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

$body = "{""name"":""$rulename"",""description"":""$ruledescription"",""type"":""External Rule""}"

$uri               = "https://$systemname/api/v1/rules"
$newrule           =  Invoke-RestMethod -Headers $headerappjson -uri $uri -body $body -Method POST -WebSession $websession
$newrule

}
