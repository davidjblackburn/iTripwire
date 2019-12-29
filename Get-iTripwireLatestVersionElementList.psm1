Function Get-iTripwireLatestVersionElementList
{
param (
    $websession,
    [string]$exists      = "True",
    [string]$elementid   = "-1y2p0ij32e8cc:-1y2p0ij32cixd",
    [string]$systemname  = "tripwire-prod.oa.caiso.com",
    [string]$logserver   = "tripwire-prod.oa.caiso.com",
    [int]$pagelimit      = 100,
    [int]$pagestart      = 0,
    [string]$logdatabase = "infosecrisks_prod",
    [string]$logtable    = "InfoSecRisksLog",
    [switch]$logtoout    = $true,
    [switch]$logtoserver = $false,
    [int]$severity       = 6
    )
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

$jsonserial                = New-Object -TypeName System.Web.Script.Serialization.JavaScriptSerializer
$jsonserial.MaxJsonLength  = [int]::MaxValue
$versionlist               = $null

$uri                       = "https://$systemname/api/v1/versions/latest?pageLimit=$pagelimit&elementId=$elementId"

$latestversions            = Invoke-RestMethod -uri $uri -Method get -WebSession $websession
$latestversionlist         = $latestversions
do
{
        $pagestart        += $pagelimit
        $uri               = "https://$systemname/api/v1/versions/latest?pageLimit=$pagelimit&pageStart=$pagestart&elementId=$elementId"
        $latestversions    = Invoke-RestMethod -uri $uri -Method get -WebSession $websession
        $latestversionlist+= $latestversions

} while ($latestversions.count -eq $pagelimit)

return $latestversionlist

}
