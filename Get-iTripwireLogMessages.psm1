<#

{
    "id": "-1y2p0ij32e8dh:-1y2p0iiw28yr2",
    "time": "2018-11-26T16:40:08.000Z",
    "level": "INFO",
    "type": "Action",
    "message": "Promoting Element ''/opt/unixteam/SERVER_Collections/collections.ksh' from Node 'aputadm6.iso.caiso.com' and Rule 'UNIXTEAM (UNIX)''.",
    "username": "dblackburn",
    "objects": [
      "-1y2p0ij32e8cc:-1y2p0iiw6pgco",
      "-1y2p0ij32e8ch:-1y2p0iiw34qls"
    ]
}

#>
Function Get-iTripwireLogMessages
{
param (
    $websession,
    [string]$systemname   = "tripwire-prod.oa.caiso.com",
    [string]$logserver    = "tripwire-prod.oa.caiso.com",
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
    [array]$objects       = @("-1y2p0ij32e8cc:-1y2p0iiw6pgco"),
    #[array]$objects       = $null,
    [string]$isdisabled   = "false",
    [string]$auditenabled = "true",
    [string]$logdatabase  = "infosecrisks_prod",
    [string]$logtable     = "InfoSecRisksLog",
    [switch]$logtoout     = $true,
    [switch]$logtoserver  = $false,
    [int]$severity        = 6
    )
$syslog_Array                = Set-SyslogArr

$headerplaintext             = @{"Accept"="text/plain"}
$headerappjson               = @{"Accept"="application/json"}

$syslog_Array.facility       = 22
$syslog_Array.severity       = $severity
$syslog_Array.version        = 1
$syslog_Array.hostname       = ([System.Net.DNS]::GetHostByName('').HostName).ToLower()
$syslog_Array.appname        = ($MyInvocation.MyCommand).Name
$syslog_Array.procid         = "-"
$syslog_Array.msgid          = "calc"
$syslog_Array.structureddata = "-"
$syslog_Array.logdatabase    = $logdatabase
$syslog_Array.logserver      = $logserver
$syslog_Array.logtable       = $logtable
$syslog_Array.logtoout       = $logtoout
$syslog_Array.logtoserver    = $logtoserver


if ( $severity -lt 0 -or $severity -gt 7 )
{
    $syslog_Array.msg        = "-LogLevel must be a number in the range [0..7]. Quitting collection."
    $syslog_Array.timestamp  = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ")

    Write-SyslogArr $syslog_Array
    return
}

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
    #$c = 0
    foreach ($object in $objects)
    {
        #if ($c -gt 0)
        #{
            if ($first -gt 0)  { $uri  += "&" }
            $objectstring += 'object=' + $object
            $first++
        #}
        #else
        #{
        #    $objectstring = 'object=' + $object
        #}

        #$c++
    }
    $uri += $objectstring
    #if ($pagelimit    -gt 0)    { $uri  += "&pageStart=$pagestart"     }
    
    #if ($pagelimit    -gt 0 )   { $uri  += "&pagelimit=$pagelimit"     }    
}
else
{
    if ($id           -ne "")   { $uri  += "id=$id" }
}

$uri                    = $uri -replace ":","%3A" -replace "https%3A//","https://" -replace ",","%2C"
$logsmessages           = Invoke-RestMethod -uri $uri -Method get -WebSession $websession -Headers $headerappjson
$logsmessages
}
