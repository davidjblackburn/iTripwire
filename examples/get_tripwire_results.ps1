clear

$systemname               = "tripwire-prod.company.com"
$username                 = "tripwireuser"
$password                 = "tripwirepassword"
$hash                     = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($username+":"+$password))
$directory                = "C:\reports\" 

$filenametime             = (Get-Date).ToString("yyyyMMddHHmm")
$start_time               = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
$headerplaintext          = @{"Accept"="text/plain"}
$headerappjson            = @{"Accept"="application/json"}
$policyname               = "Required Controls" # Policy name to be included in the report. Will pull
                                                # policies that match any portion of this string.
                                                # For instance, this string would pull reports for policies
                                                # 'Windows Server Required Controls' and 'Workstation Required Controls'

$now                      = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
Write-Output "$now Login"
$websession               = Get-iTripwireLoginWebsession -hash $hash -systemname $systemname

$now                      = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
Write-Output "$now Get Nodelist"
$nodelist                 = Get-iTripwireNodesList -websession $websession -systemname $systemname

$now                      = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
write-Output "$now Get Nodelist Sort-Object -Property lastCheck -Descending"
$nodelist                 = $nodelist | Sort-Object -Property lastCheck -Descending

$now                        = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
Write-Output "$now Get Policy Test Results"
$results_temp             = Get-iTripwirePolicyTestResults -websession $websession -policyname $policyname -systemname $systemname

$now                        = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
Write-Output "$now Get Policy Test Results Sort-Object -Property PolicytestresultsNodeId"
$results                  = $results_temp | Sort-Object -Property PolicytestresultsNodeId

$now                        = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
Write-Output "$now Get Policy Test Results Where-Object {$_.PolicytestresultsState -eq FAILED}"
$resultsfailed            = $results | Where-Object {$_.PolicytestresultsState -eq "FAILED"} 

$now                        = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
Write-Output "$now Get Policy Test Results Where-Object {$_.PolicytestresultsState -eq PASSED}"
$resultspassed            = $results | Where-Object {$_.PolicytestresultsState -eq "PASSED"} 
$resultsfailed.count
$resultspassed.count

$lastnodeid                   = $null

foreach ($result in $results)
{
    $st                         = Get-Date
    $asset_name                 = $result.PolicytestresultsNodeLabel
    $nodeid                     = $result.PolicytestresultsNodeId
    $policy_name                = $result.PolicyName
    $policy_test_name           = $result.PolicytestName
    $policy_test_id             = $result.PolicytestId
    $result.PolicyNodeScope     = $null
    $result.PolicytestRules     = $null

    #NodeInformation
    $now                        = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
    #"$now node info lookup start"
    if ($lastnodeid -eq $nodeid)
    {
    }
    else
    {
        $nodeinfo                 = $nodelist -match $nodeid | Select-Object -First 1
    }
    #$nodeinfo                 = @()
    #$now                      = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
    #"$now node info lookup end"
    $result.NodeAgentVersion              = $nodeinfo.agentVersion
    $result.NodeAuditEnabled              = $nodeinfo.auditEnabled
    $result.NodeDescription               = $nodeinfo.description
    $result.NodeElementCount              = $nodeinfo.elementCount
    $result.NodeEventGeneratorEnabled     = $nodeinfo.eventGeneratorEnabled
    $result.NodeEventGeneratorInstalled   = $nodeinfo.eventGeneratorInstalled
    $result.NodeHasFailures               = $nodeinfo.hasFailures
    $result.NodeId                        = $nodeinfo.id
    $result.NodeImportedTime              = $nodeinfo.importedTime
    $result.NodeIpAddresses               = $nodeinfo.ipAddresses -join ";"
    $result.NodeIsDisabled                = $nodeinfo.isDisabled
    $result.NodeIsSocksProxy              = $nodeinfo.isSocksProxy
    $result.NodeLastCheck                 = $nodeinfo.lastCheck
    $result.NodeLastRegistration          = $nodeinfo.lastRegistration
    #$result.NodeLicenseFeatures           = $nodeinfo.licensedFeatures
    $result.NodeLicenseFeatures           = $null
    $result.NodeMacAddresses              = $nodeinfo.macAddresses
    $result.Nodemake                      = $nodeinfo.make
    $result.NodeMaxSeverity               = $nodeinfo.maxSeverity
    $result.NodeModel                     = $nodeinfo.model
    $result.NodeModifiedTime              = $nodeinfo.modifiedTime
    $result.NodeName                      = $nodeinfo.name
    $result.NodeRealTimeEnabled           = $nodeinfo.realTimeEnabled
    $result.NodeRmiHost                   = $nodeinfo.rmiHost
    $result.NodeRmiPort                   = $nodeinfo.rmiPort
    $result.NodeTags                      = ($nodeinfo.tags.'tag' | Unique) -join ";"
    $result.NodeTrackingId                = $nodeinfo.trackingId
    $result.NodeType                      = $nodeinfo.type
    $result.NodeVersion                   = $nodeinfo.version
    
    Write-Output "$now $asset_name, $policy_test_name, Total Minutes: $tm"
    if ($result.PolicytestresultsSummaryState -eq "FAILED")
    {

        #$now                      = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
        #Write-Output "$now $asset_name [$nodeid] : $policy_test_name [$policy_test_id]"
        #$nodelist | Where-Object {$_.id -eq $nodeid}
        #Test Waivers
        $waiver                            = Get-iTripwireWaiver -nodeId $result.PolicytestresultsNodeId -policyTestId $result.PolicytestId -policyId $result.PolicyId -websession $websession -systemname $systemname
        if ($waiver -ne $null)
        {
            $result.StatusEffective      = "PASSED"
            $result.WaiverStatus         = "WAIVED"
            $result.WaiverName           = $waiver.name
            $result.WaiverDescription    = $waiver.description
            $result.WaiverGrantedBy      = $waiver.grantedby
            $result.WaiverResponsible    = $waiver.responsible
            $result.WaiverStartDate      = $waiver.starttime
            $result.WaiverExpirationDate = $waiver.expiration
        }
        else
        {
            $result.StatusEffective      = "FAILED"
            $result.WaiverStatus         = "NOT WAIVED"
            $result.WaiverName           = "none"
            $result.WaiverDescription    = "none"
            $result.WaiverGrantedBy      = "none"
            $result.WaiverResponsible    = "none"
            $result.WaiverStartDate      = "none"
            $result.WaiverExpirationDate = "none"

        }

        #Test Age
        #$now                      = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
        #"$now test age lookup start"
        $policytestage                     = Get-iTripwirePolicyTestAge -policyTestId $result.PolicytestId -nodeId $result.PolicytestresultsNodeId -websession $websession -pagelimit 1000 -pagestart 0 -querytimeout 1000 -max_baseline_age_days 7 -systemname $systemname
        #$policytestage
        #$now                      = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
        #"$now test age lookup finished"
        $result.IsOverMaxDaysOld           = $policytestage.is_over_max_days_old
        $result.LastPassedDaysOld          = $policytestage.last_passed_days_old
        $result.MaxBaselineAgeDays         = $policytestage.max_baseline_age_days
    }
    else
    {
        #Test Waivers
        $result.StatusEffective      = "PASSED"
        $result.WaiverStatus         = "NOT WAIVED"
        $result.WaiverName           = "none"
        $result.WaiverDescription    = "none"
        $result.WaiverGrantedBy      = "none"
        $result.WaiverResponsible    = "none"
        $result.WaiverStartDate      = "none"
        $result.WaiverExpirationDate = "none"

        #Test Age
        $result.IsOverMaxDaysOld     = $false
        $result.LastPassedDaysOld    = 0
        $result.MaxBaselineAgeDays   = 0

    }
    $sp                              = Get-Date
    $tm                              = (New-TimeSpan -Start $st -End $sp).TotalMinutes
    $now                             = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
    Write-Output "$now $asset_name, $policy_test_name, Total Minutes: $tm"
    $lastnodeid                      = $nodeid

}

#($results | Where-Object {$_.StatusEffective -eq "FAILED" -and $_.IsOverMaxDaysOld -eq $true -and $_.WaiverStatus -eq "NOT WAIVED" }).count

$policynamet  = $policyname -replace " ","_"
$filename     = ($directory + $filenametime + "_Tripwire_Results_" + $policynamet + ".csv").ToLower()

$results | Select PolicyId, PolicyName, PolicyDescription, PolicyModifiedTime, PolicyImportedTime, PolicyTrackingId, PolicyPurgeOldData `
                                                   , PolicyPurgeDataOlderThanDays, PolicyNodeScope ,PolicytestId, PolicytestName, PolicytestDescription, PolicytestTrackingId, PolicytestSeverity, PolicytestModifiedTime `
                                                   , PolicytestImportedTime, PolicytestType, PolicytestRules, PolicytestElementNameConditions, PolicytestVersionConditions `
                                             , PolicytestresultsId, PolicytestresultsPolicyTestId, PolicytestresultsPolicyTestName, PolicytestresultsElementId `
                                             , PolicytestresultsElementName, PolicytestresultsElementVersionId, PolicytestresultsNodeId, PolicytestresultsNodeLabel `
                                             , PolicytestresultsState, PolicytestresultsCreationTime, PolicytestresultsExpected, PolicytestresultsActual, PolicytestresultsSummaryState `
                                             ,@{n='VersionContent';e={$len=($_.VersionContent).length; if ($len -gt 32750) {"Too much content for single cell"} else { ($_.VersionContent -replace '"','""')}}} `
                                             , StatusEffective, WaiverStatus, WaiverName, WaiverDescription, WaiverGrantedBy, WaiverResponsible, WaiverStartDate, WaiverExpirationDate `
                                             , IsOverMaxDaysOld, LastPassedDaysOld, MaxBaselineAgeDays `
                                             , NodeAgentVersion, NodeAuditEnabled, NodeDescription, NodeElementCount, NodeEventGeneratorEnabled, NodeEventGeneratorInstalled `
                                                   , NodeHasFailures, NodeId, NodeImportedTime, NodeIpAddresses, NodeIsDisabled, NodeIsSocksProxy, NodeLastCheck, NodeLastRegistration `
                                                   , NodeLicenseFeatures, NodeMacAddresses, Nodemake, NodeMaxSeverity, NodeModel, NodeModifiedTime, NodeName, NodeRealTimeEnabled `
                                                   , NodeRmiHost, NodeRmiPort, NodeTags, NodeTrackingId, NodeType, NodeVersion `
         | Export-Csv $filename -NoTypeInformation

$end_time     = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
$run_time     = New-TimeSpan -start $start_time -end $end_time
Write-Output "Start time: $start_time End time: $end_time Run time: $run_time"
