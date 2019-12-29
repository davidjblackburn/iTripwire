Function Get-iTripwirePolicyTestAge
{
param (
            $websession,
    [string]$policytestid             = "-1y2p0ij32e88h:-1y2p0ij317baw",  # Use a policyId for testing.
    [string]$nodeid                   = "-1y2p0ij39e2bv:-1y2p0ij29b9jb",  # Use a nodeId for testing.
    [int]   $max_baseline_age_days    = 14,                               # Baselines over 14 days old
    [int]   $pagelimit                = 100,
    [int]   $pagestart                = 0,
    [int]   $querytimeout             = 300,
    [string]$systemname               = "tripwire-prod.company.com" # Use the Tripwire server name.
    )

$headerplaintext             = @{"Accept"="text/plain"}
$headerappjson               = @{"Accept"="application/json"}

$info                 = "" | Select-Object is_over_max_days_old, last_passed_days_old, max_baseline_age_days

# Collect policy test results
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

# Find most recent PASSED test
$last_passed_date             = ($resultslist | Sort-Object -Property creationTime -Descending | Select-Object creationTime -First 1).creationTime
if ($last_passed_date -eq $null)
{

    # Find oldest FAILED test
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

$info

}
