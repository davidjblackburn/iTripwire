Function Get-iTripwirePolicyTestResults
{
param (
    [string]$server          = "tripwire-prod.oa.caiso.com",
    [string]$policyname      = "CAISO Required Controls",
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

$uri           = "https://$server/api/v1/policies?pageLimit=$pagelimit&pageStart=$pagestart"

if ( $severity -ge 6 )
{
    $syslog_Array.msg        = "Get list of Tripwire policies"
    $syslog_Array.timestamp  = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
    Write-SyslogArr $syslog_Array
}

$results       = Invoke-RestMethod -uri $uri -Method get -WebSession $websession
$policylist    = $results
$pagestart_t   = $pagestart

if ($results.count -eq $pagelimit)
{
    do
    {
            $pagestart_t       += $pagelimit
            $uri                = "https://$server/api/v1/policies?pageLimit=$pagelimit&pageStart=$pagestart_t"
            $results            = Invoke-RestMethod -uri $uri -Method get -WebSession $websession
            $policylist        += $results

    } while ($results.count -eq $pagelimit)
}

if ( $severity -ge 6 )
{
    $syslog_Array.msg        = "Get list of Tripwire policies matching '$policyname'"
    $syslog_Array.timestamp  = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
    Write-SyslogArr $syslog_Array
}

$policiescaisorequired         = $policylist | Where-Object {$_.name -match $policyname}

$resultstemplate                = $null
$resultstemplate                = "" | Select PolicyId, PolicyName, PolicyDescription, PolicyModifiedTime, PolicyImportedTime, PolicyTrackingId, PolicyPurgeOldData `
                                                   , PolicyPurgeDataOlderThanDays, PolicyNodeScope ,PolicytestId, PolicytestName, PolicytestDescription, PolicytestTrackingId, PolicytestSeverity, PolicytestModifiedTime `
                                                   , PolicytestImportedTime, PolicytestType, PolicytestRules, PolicytestElementNameConditions, PolicytestVersionConditions `
                                             , PolicytestresultsId, PolicytestresultsPolicyTestId, PolicytestresultsPolicyTestName, PolicytestresultsElementId `
                                             , PolicytestresultsElementName, PolicytestresultsElementVersionId, PolicytestresultsNodeId, PolicytestresultsNodeLabel `
                                             , PolicytestresultsState, PolicytestresultsCreationTime, PolicytestresultsExpected, PolicytestresultsActual, PolicytestresultsSummaryState `
                                             , VersionContent `
                                             , StatusEffective, WaiverStatus, WaiverName, WaiverDescription, WaiverGrantedBy, WaiverResponsible, WaiverStartDate, WaiverExpirationDate `
                                             , IsOverMaxDaysOld, LastPassedDaysOld, MaxBaselineAgeDays `
                                             , NodeAgentVersion, NodeAuditEnabled, NodeDescription, NodeElementCount, NodeEventGeneratorEnabled, NodeEventGeneratorInstalled `
                                                   , NodeHasFailures, NodeId, NodeImportedTime, NodeIpAddresses, NodeIsDisabled, NodeIsSocksProxy, NodeLastCheck, NodeLastRegistration `
                                                   , NodeLicenseFeatures, NodeMacAddresses, Nodemake, NodeMaxSeverity, NodeModel, NodeModifiedTime, NodeName, NodeRealTimeEnabled `
                                                   , NodeRmiHost, NodeRmiPort, NodeTags, NodeTrackingId, NodeType, NodeVersion
$results                        = @()
$results_t                      = @()

foreach ($policy in $policiescaisorequired)
{

    # Pull policy test names by policyId
    $policyId                     = $policy.id
    $policyName                   = $policy.name
    $policyDescription            = $policy.description
    $policyModifiedTime           = $policy.modifiedtime
    $policyImportedTime           = $policy.importedtime
    $policytrackingId             = $policy.trackingid
    $policyPurgeOldData           = $policy.purgeolddata
    $policyPurgeDataOlderThanDays = $policy.purgedataolderthandays
    $policyNodeScope              = $policy.nodescope
    
    $pagestart_t     = $pagestart

    $uri             = "https://$server/api/v1/policytests?policyId=$policyId"

    if ( $severity -ge 6 )
    {
        $syslog_Array.msg        = "Get Policy tests for $policyName"
        $syslog_Array.timestamp  = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
        Write-SyslogArr $syslog_Array
    }

    $policytestlist  = Invoke-RestMethod -uri $uri -Method get -WebSession $websession -Headers $headerappjson
    
    foreach ($policytest in $policytestlist)
    {
            $policytestId                    = $policytest.id
            $policytestName                  = $policytest.name
            $policytestDescription           = $policytest.description
            $policytestTrackingId            = $policytest.trackingid
            $policytestSeverity              = $policytest.severity
            $policytestModifiedTime          = $policytest.modifiedtime
            $policytestImportedTime          = $policytest.importedtime
            $policytestType                  = $policytest.type
            $policytestRules                 = $policytest.rules
            $policytestElementNameConditions = $policytest.elementnameconditions
            $policytestVersionConditions     = $policytest.versionconditions

            if ( $severity -ge 6 )
            {
                $syslog_Array.msg        = "Get Policy test results for $policyname : $policytestName"
                $syslog_Array.timestamp  = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
                Write-SyslogArr $syslog_Array
            }

            $pagestart_t              = $pagestart
            $uri                      = "https://tripwire-prod.oa.caiso.com/api/v1/policytestresults/latest?policyTestId=$policytestId&pageLimit=$pagelimit&pageStart=$pagestart_t"
            $results                  = Invoke-RestMethod -Uri $uri -Method get -WebSession $websession -Headers $headerappjson
            $policytestresultslist    = $results

            if ($results.count -eq $pagelimit)
            {
                do
                {
                        $pagestart_t                  += $pagelimit
                        $uri                           = "https://tripwire-prod.oa.caiso.com/api/v1/policytestresults/latest?policyTestId=$policytestId&pageLimit=$pagelimit&pageStart=$pagestart_t"
                        $results                       = Invoke-RestMethod -uri $uri -Method get -WebSession $websession
                        $policytestresultslist        += $results

                        if ( $severity -ge 7 )
                        {
                            $syslog_Array.msg        = "Get Policy test results for $policyname : $policytestName : $pagestart_t"
                            $syslog_Array.timestamp  = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
                            Write-SyslogArr $syslog_Array
                        }

                } while ($results.count -eq $pagelimit)
            }

            foreach($policytestresult in $policytestresultslist)
            {
                $policytestresultsId                = $policytestresult.id
                $policytestresultsPolicyTestId      = $policytestresult.policytestid
                $policytestresultsPolicyTestName    = $policytestresult.policytestname
                $policytestresultsElementId         = $policytestresult.elementid
                $policytestresultsElementName       = $policytestresult.elementname
                $policytestresultsElementVersionId  = $policytestresult.elementversionid
                $policytestresultsNodeId            = $policytestresult.nodeid
                $policytestresultsNodeLabel         = ($policytestresult.nodelabel).ToLower()
                $policytestresultsState             = $policytestresult.state
                $policytestresultsCreationTime      = $policytestresult.creationtime
                $policytestresultsExpected          = $policytestresult.expected
                $policytestresultsActual            = $policytestresult.actual
                $policytestresultsSummaryState      = $policytestresult.summarystate

                if ( $severity -ge 6 )
                {
                    $syslog_Array.msg        = "Get Policy test results for $policyname : $policytestName : $policytestresultsNodeLabel"
                    $syslog_Array.timestamp  = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
                    Write-SyslogArr $syslog_Array
                }

                if ($policytestresultsState -eq "FAILED")
                {
                    $versioncontent       = $null
                    $uri                  = "https://$server/api/v1/versions/$policytestresultsElementVersionId"
                    $versioncontente      = Invoke-RestMethod -uri $uri -Method get -WebSession $websession -Headers $headerappjson
                    $versioncontentexists = $versioncontente.exists
                    $versioncontentmd5    = $versioncontente.md5
                    $versioncontentsha1   = $versioncontente.sha1
                    $versioncontentsha256 = $versioncontente.sha256
                    $versioncontentsha512 = $versioncontente.sha512

                    if ($versioncontentexists -eq $true)
                    {
                            $uri                = "https://$server/api/v1/versions/$policytestresultsElementVersionId/attributes"
                            $versioncontenta     = Invoke-RestMethod -uri $uri -Method get -WebSession $websession -Headers $headerappjson
                            $versioncontentavalue= $versioncontente.md5
                            if ($versioncontentavalue -eq "d41d8cd98f00b204e9800998ecf8427e")
                            {
                                $versioncontent     = "No Content"
                            }
                            else
                            {
                                if ($versioncontentmd5.length -gt 0 -or $versioncontentsha1.length -gt 0 -or $versioncontentsha256.length -gt 0 -or $versioncontentsha512.length -gt 0)
                                {
                                    $uri                = "https://$server/api/v1/versions/$policytestresultsElementVersionId/content"
                                    $versioncontent     = Invoke-RestMethod -uri $uri -Method get -WebSession $websession -Headers $headerplaintext
                                }
                                else
                                {
                                    #$uri                = "https://$server/api/v1/versions/$elementversionid/attributes"
                                    #$versioncontent     = Invoke-RestMethod -uri $uri -Method get -WebSession $websession -Headers $headerappjson
                                    $versioncontent     = "Multiple attributes"
                                }
                            }
                    }
                    else
                    {
                        $versioncontent     = "No Content"
                    }
                }
                 else
                {
                    $versioncontent     = "Check passed: not collected"
                }


                #Write-Output "$policyName ## $policytestName ## $nodelabel ## $state"
                #Write-Output "$policyName"
                $resultstemplate_t      = $null
                $resultstemplate_t      = "" | Select PolicyId, PolicyName, PolicyDescription, PolicyModifiedTime, PolicyImportedTime, PolicyTrackingId, PolicyPurgeOldData `
                                                   , PolicyPurgeDataOlderThanDays, PolicyNodeScope ,PolicytestId, PolicytestName, PolicytestDescription, PolicytestTrackingId, PolicytestSeverity, PolicytestModifiedTime `
                                                   , PolicytestImportedTime, PolicytestType, PolicytestRules, PolicytestElementNameConditions, PolicytestVersionConditions `
                                             , PolicytestresultsId, PolicytestresultsPolicyTestId, PolicytestresultsPolicyTestName, PolicytestresultsElementId `
                                             , PolicytestresultsElementName, PolicytestresultsElementVersionId, PolicytestresultsNodeId, PolicytestresultsNodeLabel `
                                             , PolicytestresultsState, PolicytestresultsCreationTime, PolicytestresultsExpected, PolicytestresultsActual, PolicytestresultsSummaryState `
                                             , VersionContent `
                                             , StatusEffective, WaiverStatus, WaiverName, WaiverDescription, WaiverGrantedBy, WaiverResponsible, WaiverStartDate, WaiverExpirationDate `
                                             , IsOverMaxDaysOld, LastPassedDaysOld, MaxBaselineAgeDays `
                                             , NodeAgentVersion, NodeAuditEnabled, NodeDescription, NodeElementCount, NodeEventGeneratorEnabled, NodeEventGeneratorInstalled `
                                                   , NodeHasFailures, NodeId, NodeImportedTime, NodeIpAddresses, NodeIsDisabled, NodeIsSocksProxy, NodeLastCheck, NodeLastRegistration `
                                                   , NodeLicenseFeatures, NodeMacAddresses, Nodemake, NodeMaxSeverity, NodeModel, NodeModifiedTime, NodeName, NodeRealTimeEnabled `
                                                   , NodeRmiHost, NodeRmiPort, NodeTags, NodeTrackingId, NodeType, NodeVersion
$results                        = @()

                #POLICY: PolicyId, PolicyName, PolicyDescription, PolicyModifiedTime, PolicyImportedTime, PolicyTrackingId, PolicyPurgeOldData, Policy, purgeDataOlderThanDays, PolicynodeScope
                $resultstemplate_t.PolicyId                            = $policyId
                $resultstemplate_t.PolicyName                          = $policyName
                $resultstemplate_t.PolicyDescription                   = $policyDescription
                $resultstemplate_t.PolicyModifiedTime                  = $policyModifiedTime
                $resultstemplate_t.PolicyImportedTime                  = $policyImportedTime
                $resultstemplate_t.PolicyTrackingId                    = $policyTrackingId
                $resultstemplate_t.PolicyPurgeOldData                  = $policyPurgeOldData
                $resultstemplate_t.PolicyPurgeDataOlderThanDays        = $policyPurgeDataOlderThanDays
                $resultstemplate_t.PolicynodeScope                     = $policyNodeScope

                #POLICY TEST: PolicytestId, PolicytestName, PolicytestDescription, PolicytestTrackingId, PolicytestSeverity, PolicytestModifiedTime, PolicytestImportedTime, PolicytestType, PolicytestRules, PolicytestElementNameConditions, PolicytestVersionConditions
                $resultstemplate_t.PolicytestId                        = $policytestId
                $resultstemplate_t.PolicytestName                      = $policytestName
                $resultstemplate_t.PolicytestDescription               = $policytestDescription
                $resultstemplate_t.PolicytestTrackingId                = $policytestTrackingId
                $resultstemplate_t.PolicytestSeverity                  = $policytestSeverity
                $resultstemplate_t.PolicytestModifiedTime              = $policytestModifiedTime
                $resultstemplate_t.PolicytestImportedTime              = $policytestImportedTime
                $resultstemplate_t.PolicytestType                      = $policytestType
                $resultstemplate_t.PolicytestRules                     = $policytestRules
                $resultstemplate_t.PolicytestElementNameConditions     = $policytestElementNameConditions
                $resultstemplate_t.PolicytestVersionConditions         = $policytestVersionConditions

                #POLICY TEST RESULT: PolicytestresultsId, PolicytestresultsPolicyTestId, PolicytestresultsPolicyTestName, PolicytestresultsElementId, PolicytestresultsElementName, PolicytestresultsElementVersionId, PolicytestresultsNodeId, PolicytestresultsNodeLabel, PolicytestresultsState, PolicytestresultsCreationTime, PolicytestresultsExpected, PolicytestresultsActual, PolicytestresultsSummaryState
                $resultstemplate_t.PolicytestresultsId                 = $policytestresultsId
                $resultstemplate_t.PolicytestresultsPolicyTestId       = $policytestresultsPolicyTestId
                $resultstemplate_t.PolicytestresultsPolicyTestName     = $policytestresultsPolicyTestName
                $resultstemplate_t.PolicytestresultsElementId          = $policytestresultsElementId
                $resultstemplate_t.PolicytestresultsElementName        = $policytestresultsElementName
                $resultstemplate_t.PolicytestresultsElementVersionId   = $policytestresultsElementVersionId
                $resultstemplate_t.PolicytestresultsNodeId             = $policytestresultsNodeId
                $resultstemplate_t.PolicytestresultsNodeLabel          = $policytestresultsNodeLabel
                $resultstemplate_t.PolicytestresultsState              = $policytestresultsState
                $resultstemplate_t.PolicytestresultsCreationTime       = $policytestresultsCreationTime
                $resultstemplate_t.PolicytestresultsExpected           = $policytestresultsExpected
                $resultstemplate_t.PolicytestresultsActual             = $policytestresultsActual
                $resultstemplate_t.PolicytestresultsSummaryState       = $policytestresultsSummaryState

                #RESULT CONTENT: VersionContent
                $resultstemplate_t.VersionContent                      = $versioncontent
                if ($results_t -eq $null)
                {
                    $results_t                                         = $resultstemplate_t
                }
                else
                {
                    $results_t                                        += $resultstemplate_t
                }
            }

    }
  

}

$timespan                    = (New-TimeSpan -Start $start_time -End (Get-Date)).TotalMinutes
if ( $severity -ge 6 )
{
    $syslog_Array.msg        = "End script after $timespan minutes"
    $syslog_Array.timestamp  = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
    Write-SyslogArr $syslog_Array
}

$results_t

}
