Function Set-iTripwireLogMessages
{
param (
    $websession,
    [string]$systemname  = "tripwire-prod.company.com",           # Use the Tripwire server name.
    [string]$time,
    [string]$level       = "INFO",     #ERROR, INFO, UNKNOWN
    [string]$type        = "System",   #system, tacacs, radius, soap client
    [string]$message,
    [array]$objects
    )

$headerplaintext             = @{"Accept"="text/plain"}
$headerappjson               = @{"Accept"="application/json"}

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

if ($time -eq "")
{
    $time = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
}

if ($objects -ne "")
{
    $c = 0
    foreach ($object in $objects)
    {
        if ($c -gt 0)
        {
            $objectstring += ',"' + $object + '"'
        }
        else
        {
            $objectstring = '"' + $object + '"'
        }

        $c++
    }
}
else
{

    # No objects. Ending Function Set-iTripwireLogMessages.
    return
}

if ($message -ne "")
{
    $body = 
    "
    {
        ""time"": ""$time"",
        ""level"": ""$level"",
        ""type"": ""$type"",
        ""message"": ""$message"",
        ""objects"": [
            $objectstring
        ]
    }

    "
}

$uri                      = "https://$systemname/api/v1/logMessages"
$nodes                    = Invoke-RestMethod -headers $headerappjson -uri $uri -body $body -Method POST -WebSession $websession

}
