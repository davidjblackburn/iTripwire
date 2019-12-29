Function Get-iTripwirePolicyTestAge
{
param (
            $websession,
    [string]$policytestid             = "-1y2p0ij32e88h:-1y2p0ij317baw",
    [string]$nodeid                   = "-1y2p0ij317d4g:-1y2p0ij30lxhu",
    [int]   $max_baseline_age_days    = 14,
    [int]   $pagelimit                = 100,
    [int]   $pagestart                = 0,
    [int]   $querytimeout             = 300,
    [string]$tripwirehistorytable     = "risk_tripwire_compliance_tests_history",
    [string]$systemname               = "tripwire-prod.oa.caiso.com",
    [string]$logserver                = "tripwire-prod.oa.caiso.com",
    [string]$logdatabase              = "infosecrisks_prod",
    [string]$logtable                 = "infosecrisksLog",
    [switch]$logtoout                 = $false,
    [switch]$logtoserver              = $false,
    [int]$severity                    = 6
    )
$start_time                  = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
$headerplaintext             = @{"Accept"="text/plain"}
$headerappjson               = @{"Accept"="application/json"}

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
$info                 = "" | Select-Object is_over_max_days_old, last_passed_days_old, max_baseline_age_days


if ( $severity -ge 6 )
{
    $syslog_Array.msg        = "Collect policy test results"
    $syslog_Array.timestamp  = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
    Write-SyslogArr $syslog_Array
}

$pagestart_t          = $pagestart
$uri                  = "https://$systemname/api/v1/policytestresults?policyTestId=$policytestid&nodeId=$nodeid&state=PASSED&pageLimit=$pagelimit&pageStart=$pagestart_t"
try
{
    $results              = Invoke-RestMethod -uri $uri -Method get -WebSession $websession -Headers $headerappjson -TimeoutSec $querytimeout
}
catch
{
    $info.last_passed_days_old    = "666.6"
    $info.max_baseline_age_days   = $max_baseline_age_days
    $info.is_over_max_days_old    = $true
    return $info
}

$resultslist          = $results

if ($results.count -eq $pagelimit)
{
    do
    {
            $pagestart_t       += $pagelimit
            $uri                = "https://$systemname/api/v1/policytestresults?policyTestId=$policytestid&nodeId=$nodeid&state=PASSED&pageLimit=$pagelimit&pageStart=$pagestart_t"
            $results            = Invoke-RestMethod -uri $uri -Method get -WebSession $websession -Headers $headerappjson -TimeoutSec $querytimeout
            $resultslist       += $results

    } while ($results.count -eq $pagelimit)
}

#$resultslist                   = $resultslist | Where-Object {$_.PolicytestresultsNodeId -eq $nodeId}

if ( $severity -ge 6 )
{
    $syslog_Array.msg         = "Find most recent PASSED test"
    $syslog_Array.timestamp   = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
    Write-SyslogArr $syslog_Array
}

$last_passed_date             = ($resultslist | Sort-Object -Property creationTime -Descending | Select-Object creationTime -First 1).creationTime
if ($last_passed_date -eq $null)
{
    #$info.last_passed_days_old  = 0
    #$info.is_over_max_days_old   = $false
    if ( $severity -ge 6 )
    {
        $syslog_Array.msg         = "Find oldest FAILED test"
        $syslog_Array.timestamp   = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
        Write-SyslogArr $syslog_Array
    }
    $pagestart_t          = $pagestart
    $uri                  = "https://$systemname/api/v1/policytestresults?policyTestId=$policytestid&nodeId=$nodeid&state=FAILED&pageLimit=$pagelimit&pageStart=$pagestart_t"
    $results              = Invoke-RestMethod -uri $uri -Method get -WebSession $websession -Headers $headerappjson -TimeoutSec $querytimeout <# Try catch needed #>
    $resultslist          = $results

    if ($results.count -eq $pagelimit)
    {
        do
        {
                $pagestart_t       += $pagelimit
                $uri                = "https://$systemname/api/v1/policytestresults?policyTestId=$policytestid&nodeId=$nodeid&state=FAILED&pageLimit=$pagelimit&pageStart=$pagestart_t"
                $results            = Invoke-RestMethod -uri $uri -Method get -WebSession $websession -Headers $headerappjson -TimeoutSec $querytimeout
                $resultslist       += $results

        } while ($results.count -eq $pagelimit)
    }
    #$resultslist                   = $resultslist | Where-Object {$_.PolicytestresultsNodeId -eq $nodeId}
    $first_failed_date             = ($resultslist | Sort-Object -Property creationTime | Select-Object creationTime -First 1).creationTime
    if ($first_failed_date -eq $null)
    {
    }
    else
    {
        $info.last_passed_days_old    = (New-TimeSpan -start $first_failed_date -end $start_time).TotalDays
        $info.max_baseline_age_days   = $max_baseline_age_days
        if ($info.last_passed_days_old -gt $max_baseline_age_days)
        {
            $info.is_over_max_days_old = $true
        }
        else
        {
            $info.is_over_max_days_old = $false
        }
    }
}
else
{
    $info.last_passed_days_old    = (New-TimeSpan -start $last_passed_date -end $start_time).TotalDays

    if ($info.last_passed_days_old -gt $max_baseline_age_days)
    {
        $info.is_over_max_days_old = $true
    }
    else
    {
        $info.is_over_max_days_old = $false
    }

}

$info.max_baseline_age_days  = $max_baseline_age_days

$timespan                    = (New-TimeSpan -Start $start_time -End ((Get-Date).ToUniversalTime())).TotalMinutes
if ( $severity -ge 6 )
{
    $syslog_Array.msg        = "End script after $timespan minutes"
    $syslog_Array.timestamp  = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
    Write-SyslogArr $syslog_Array
}

$info

}
