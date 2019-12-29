Function Get-iTripwirePolicyTests
{
param (
    [string]$server          = "tripwire-prod.oa.caiso.com",
    [string]$policyId        = "",
            $websession,
    [int]   $pagelimit       = 100,
    [int]   $pagestart       = 0,
    [string]$logserver       = "tripwire-prod.oa.caiso.com",
    [string]$logdatabase     = "infosecrisks_prod",
    [string]$logtable        = "infosecrisksLog",
    [switch]$logtoout        = $false,
    [switch]$logtoserver     = $false,
    [int]$severity           = 6

)

$start_time                  = Get-Date

$syslog_Array                = Set-SyslogArr

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

if ( $severity -ge 6 )
{
    $syslog_Array.msg        = "Start script"
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

$headerplaintext = @{"Accept"="text/plain"}
$headerappjson   = @{"Accept"="application/json"}

$uri           = "https://$server/api/v1/policytests?policyId=$policyId&pageLimit=$pagelimit&pageStart=$pagestart"

if ( $severity -ge 6 )
{
    $syslog_Array.msg        = "Get list of Tripwire policies"
    $syslog_Array.timestamp  = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
    Write-SyslogArr $syslog_Array
}

$results       = Invoke-RestMethod -uri $uri -Method get -WebSession $websession
$policytests   = $results
$pagestart_t   = $pagestart

if ($results.count -eq $pagelimit)
{
    do
    {
            $pagestart_t       += $pagelimit
            $uri                = "https://$server/api/v1/policytests?policyId=$policyId&pageLimit=$pagelimit&pageStart=$pagestart_t"
            $results            = Invoke-RestMethod -uri $uri -Method get -WebSession $websession
            $policytests       += $results

    } while ($results.count -eq $pagelimit)
}

$timespan                    = (New-TimeSpan -Start $start_time -End (Get-Date)).TotalMinutes
if ( $severity -ge 6 )
{
    $syslog_Array.msg        = "End script after $timespan minutes"
    $syslog_Array.timestamp  = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
    Write-SyslogArr $syslog_Array
}

$policytests

}
