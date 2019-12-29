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

Function Set-iTripwireLogMessages
{
param (
    $websession,
    [string]$systemname  = "tripwire-prod.oa.caiso.com",
    [string]$logserver   = "tripwire-prod.oa.caiso.com",
    [string]$time,
    [string]$level       = "INFO",     #ERROR, INFO, UNKNOWN
    [string]$type        = "System",   #system, tacacs, radius, soap client
    [string]$message,
    [array]$objects,
    #[string]$username    = "tripwire",
    [string]$logdatabase = "infosecrisks_prod",
    [string]$logtable    = "InfoSecRisksLog",
    [switch]$logtoout    = $true,
    [switch]$logtoserver = $false,
    [int]$severity       = 6
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

if ( $severity -ge 7 )
{
    $syslog_Array.msg        = "Start script."
    $syslog_Array.timestamp  = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ")

    Write-SyslogArr $syslog_Array
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
    if ( $severity -ge 7 )
    {
        $syslog_Array.msg        = "No objects. Ending Function Set-iTripwireLogMessages."
        $syslog_Array.timestamp  = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ")

        Write-SyslogArr $syslog_Array
        return
    }
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

if ( $severity -ge 7 )
{
    $syslog_Array.msg        = "Stop script."
    $syslog_Array.timestamp  = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ")

    Write-SyslogArr $syslog_Array
}

}
