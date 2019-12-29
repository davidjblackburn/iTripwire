Function Get-iTripwireElementsList
{
param (
    $websession,
    [string]$ruleid      = "-1y2p0lj36e7m7:-1y2p0ij42wmy7", # Use a ruleId for testing.
    [string]$systemname  = "tripwire-prod.company.com",     # Use the Tripwire server name.
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

$jsonserial               = New-Object -TypeName System.Web.Script.Serialization.JavaScriptSerializer
$jsonserial.MaxJsonLength = [int]::MaxValue
$elementslist             = $null

$uri                      = "https://$systemname/api/v1/elements?ruleId=$ruleid"

$elements                 = Invoke-RestMethod -uri $uri -Method get -WebSession $websession -Headers $headerappjson

if (($elements.GetType()).BaseType.Name -ne "Array" )
{
    $elementslist         = $jsonserial.Deserialize($elements,[System.Object])
}
else
{
    $elementslist         = $elements
}

return $elementslist

}
