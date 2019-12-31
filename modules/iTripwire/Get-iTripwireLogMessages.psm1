Function Get-iTripwireLogMessages
{
param (
    $websession,
    [string]$systemname   = "tripwire-prod.company.com",       # Use the Tripwire server name.
    [int]$pagelimit       = 0,
    [int]$pagestart       = 0,
    [string]$id           = $null,
    [string]$level        = $null,
    [string]$time         = $null,
    [string]$timerange    = $null,
    [string]$type         = $null,
    [string]$message      = $null,
    [string]$sub_message  = $null,
    [string]$username     = $null,
    [array]$objects       = @("-1y2p0ij36e7cc:-1y2p0ijw3pgci"), # Use array of objectIds for testing.
    [string]$isdisabled   = "false",
    [string]$auditenabled = "true"
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

$uri                      = "https://$systemname/api/v1/logMessages?"
$first                    = 0 
if ($objects -ne "")
{

    
    if ($id           -ne "")   {   if ($first -gt 0)  { $uri  += "&" }
                                    $uri  += "id=$id"
                                    $first ++         }
    if ($level        -ne "")   {    if ($first -gt 0)  { $uri  += "&" }
                                    $uri  += "level=$level"
                                    $first ++         }
    if ($time         -ne "")   {    if ($first -gt 0)  { $uri  += "&" }
                                    $uri  += "time=$time"
                                    $first ++               }
    if ($timerange    -ne "")   {    if ($first -gt 0)  { $uri  += "&" }
                                    $uri  += "timeRange=$timerange"
                                    $first ++     }
    if ($type         -ne "")   {    if ($first -gt 0)  { $uri  += "&" }
                                    $uri  += "type=$type"
                                    $first ++               }
    if ($message      -ne "")   {    if ($first -gt 0)  { $uri  += "&" }
                                    $uri  += "message=$message"
                                    $first ++         }
    if ($sub_message  -ne "")   {    if ($first -gt 0)  { $uri  += "&" }
                                    $uri  += "sub_message=$sub_message"
                                    $first ++ }
    if ($username     -ne "")   {    if ($first -gt 0)  { $uri  += "&" }
                                    $uri  += "username=$username"
                                    $first ++       }

    foreach ($object in $objects)
    {
        if ($first -gt 0)  { $uri  += "&" }
        $objectstring += 'object=' + $object
        $first++
    }
    $uri += $objectstring

}
else
{
    if ($id           -ne "")   { $uri  += "id=$id" }
}

$uri                    = $uri -replace ":","%3A" -replace "https%3A//","https://" -replace ",","%2C"
$logsmessages           = Invoke-RestMethod -uri $uri -Method get -WebSession $websession -Headers $headerappjson
$logsmessages
}
