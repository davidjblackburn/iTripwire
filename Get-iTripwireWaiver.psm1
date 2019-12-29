Function Get-iTripwireWaiver
{
param (
    $websession,
    [string]$policyId,
    [string]$policyTestId,
    [string]$nodeId,
    [string]$systemname               = "tripwire-prod.oa.caiso.com",
    [string]$logserver                = "tripwire-prod.oa.caiso.com",
    [string]$logdatabase              = "infosecrisks_prod",
    [string]$logtable                 = "infosecrisksLog",
    [switch]$logtoout                 = $false,
    [switch]$logtoserver              = $false,
    [int]$severity                    = 6
    )
$start_time                  = Get-Date

$headerplaintext             = @{"Accept"="text/plain"}
$headerappjson               = @{"Accept"="application/json"}
$results                     = $null

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

if ( $severity -ge 6 )
{
    $syslog_Array.msg        = "Get complete list of waivers"
    $syslog_Array.timestamp  = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
    Write-SyslogArr $syslog_Array
}

$waiverlist                  = Get-iTripwirePolicyTestWaivers -websession $websession

if ( $severity -ge 6 )
{
    $syslog_Array.msg        = "Find PolicyId for test to check for waiver"
    $syslog_Array.timestamp  = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
    Write-SyslogArr $syslog_Array
}

$policyresults               = $waiverlist | Where-Object { $_.policyId -eq $policyId }

if ($policyresults.count -gt 0 -or $policyresults.id.Length -gt 0 )
{
    $results                     = $policyresults | Where-Object { $_.waivedTests.nodeid -eq $nodeId -and $_.waivedTests.policytestid -eq $policyTestId } | Sort-Object -Property expiration -Descending | Select-Object -First 1
}

$results

$timespan                    = (New-TimeSpan -Start $start_time -End (Get-Date)).TotalMinutes
if ( $severity -ge 6 )
{
    $syslog_Array.msg        = "End script after $timespan minutes"
    $syslog_Array.timestamp  = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
    Write-SyslogArr $syslog_Array
}

}
