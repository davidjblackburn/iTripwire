﻿Function Get-iTripwireVersionList
{
param (
    $websession,
    [string]$exists      = "True",
    [string]$nodeId      = "-1y2p0ij32e8bv:-1y2p0ij32e7c4",    #nodeId fop FTRIPWIREP05
    [string]$ruleId      = "-1y2p0ij32e8b6:-1y2p0ij31ssp3",    #nodeId fop FTRIPWIREP05
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

$uri                       = "https://$systemname/api/v1/versions?exists=true&pageLimit=$pagelimit&nodeId=$nodeId&ruleId=$ruleid"

$versions                  = Invoke-RestMethod -uri $uri -Method get -WebSession $websession
$versionslist              = $versions
do
{
        $pagestart        += $pagelimit
        $uri               = "https://$systemname/api/v1/versions?exists=true&pageLimit=$pagelimit&pageStart=$pagestart&nodeId=$nodeId&ruleId=$ruleid"
        $versions          = Invoke-RestMethod -uri $uri -Method get -WebSession $websession
        $versionslist      += $versions

} while ($versions.count -eq $pagelimit)

return $versionslist

}