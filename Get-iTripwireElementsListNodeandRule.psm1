Function Get-iTripwireElementsListNodeandRule
{
param (
    $websession,
    [string]$ruleid      = "-1y2p0ij32e7pq:-1y2p0ij30b3m3",
    [string]$nodeid      = "-1y2p0ij32e8bv:-1y2p0ij30b7jb",
    [string]$systemname  = "tripwire-prod.oa.caiso.com",
    [string]$logserver   = "tripwire-prod.oa.caiso.com",
    [int]$pagelimit      = 100,
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

$elementslist             = @()

$uri                      = "https://$systemname/api/v1/elements?nodeId=$nodeid&ruleId=$ruleid&pageLimit=$pageLimit"

$elements                 = Invoke-RestMethod -uri $uri -Method get -WebSession $websession -Headers $headerappjson
$elementslist            += $elements
$elementscount            = $elements.count
do 
{
    $previousId               = $elements[$pageLimit-1].id
    $uri                      = "https://$systemname/api/v1/elements?nodeId=$nodeid&ruleId=$ruleid&pageLimit=$pageLimit&previousId=$previousId"
    $elements                 = Invoke-RestMethod -uri $uri -Method get -WebSession $websession -Headers $headerappjson
    $elementscount            = $elements.count
    $elementslist            += $elements
}
while ($elementscount -eq $pagelimit)

return $elementslist

}
