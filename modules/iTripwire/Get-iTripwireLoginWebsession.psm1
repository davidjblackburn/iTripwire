Function Get-iTripwireLoginWebsession
{
param (
    [string]$username    = "",
    [string]$password    = "",
    [string]$hash        = "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx=", # Put basic hash here.
    [string]$systemname  = "tripwire-prod.company.com"
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

if ($username -ne "" -and $password -ne "")
{
    $hash           = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($username+":"+$password))
}

if ($hash -eq $null)
{
    return
}

$hash            = "Basic " + $hash
$headers         = @{"Accept"="application/json";"Content-Type"="application/json";"X-Requested-With"="TE-REST-API";"Authorization"="$hash"}
$uri             = "https://$systemname/api/v1/csrf-token"
$tokenresponse   = Invoke-RestMethod -Uri $uri -Method Get -headers $headers -SessionVariable websession -MaximumRedirection 0
$token           = $tokenresponse.tokenvalue
$headers         = @{"CSRFToken"="$token"}
$uri             = "https://$systemname/api/v1/status"
$result          = Invoke-RestMethod -Uri $uri -Method Get -headers $headers -WebSession $websession
return $websession

}
