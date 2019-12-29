Function Get-iTripwireUnknownPolicyTestResults
{
param (
            $websession,
    [string]$policyId                 = "-1y2p0ij32e886:-1y2p0ij32bzxz",
    #[string]$policyTestId             = "-1y2p0ij32e88h:-1y2p0ij32bzs0",
    [string]$systemname               = "tripwire-prod.oa.caiso.com",
    [string]$logserver                = "tripwire-prod.oa.caiso.com",
    [string]$logdatabase              = "infosecrisks_prod",
    [string]$logtable                 = "infosecrisksLog",
    [switch]$logtoout                 = $false,
    [switch]$logtoserver              = $false,
    [int]$severity                    = 6
    )
$start_time                  = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
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
$info                 = "" | Select-Object is_over_14_days_old, last_passed_days_old


if ( $severity -ge 6 )
{
    $syslog_Array.msg        = "Collect unknown policy test results"
    $syslog_Array.timestamp  = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
    Write-SyslogArr $syslog_Array
}

$uri                      = "https://$systemname/api/v1/policytestresults/unknownTestResults"
$results                  = Invoke-RestMethod -uri $uri -Method get -WebSession $websession

[void][System.Reflection.Assembly]::LoadWithPartialName("System.Web.Extensions")        
$jsonserial               = New-Object -TypeName System.Web.Script.Serialization.JavaScriptSerializer 
$jsonserial.MaxJsonLength = 67108864
$resultsjson              = $jsonserial.DeserializeObject($results)
$resultsjsonpolicyid      = $resultsjson | Where-Object {$_.policyId -eq $policyId}

$results                  = $null
$resultsjson              = $null

$results_final            = @()
foreach ($ra in $resultsjsonpolicyid)
{
    $res                      = $null
    $res                      = "" | Select-Object policyId, nodeId, policyTestId
    $res.policyId             = $ra.policyId
    $res.nodeId               = $ra.nodeId
    $res.policyTestId         = $ra.policyTestId
    $results_final           += $res
}

$timespan                    = (New-TimeSpan -Start $start_time -End ((Get-Date).ToUniversalTime())).TotalMinutes
if ( $severity -ge 6 )
{
    $syslog_Array.msg        = "End script after $timespan minutes"
    $syslog_Array.timestamp  = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
    Write-SyslogArr $syslog_Array
}

$results_final

}
