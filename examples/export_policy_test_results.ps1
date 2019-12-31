clear
$now = Get-Date
"$now login"
$websession                        = Get-iTripwireLoginWebsession
$now = Get-Date
"$now nodeslist"
$nodeslist                         = Get-iTripwireNodesList -websession $websession
$now = Get-Date
"$now ruleslist"
$ruleslist                         = Get-iTripwireRulesList -websession $websession

#$now = Get-Date
#"$now latestversionlist"
#$latestversionlist                 = Get-iTripwireLatestVersionList -websession $websession #Default FTRIPWIREP05
#$now = Get-Date
"$now required baselines rules"
$ruleslistrequiredbaselineids      = $ruleslist | Where-Object {$_.description -match "#REQUIRED BASELINE#" -and $_.description -notmatch "#Custom Installed Software#" } | Select id
$ruleslistids                      = $ruleslistrequiredbaselineids.id

#$now = Get-Date
#"$now latestversionlist"

#$latestversionlistrequiredbaseline = $latestversionlist | Where-Object { $ruleslistrequiredbaselineids -match $_.ruleId } #Default FTRIPWIREP05

$command = 
"
SELECT  host_name_long
  FROM  dbo.v_current_CAISO_asset_list
  WHERE is_cip = 1
  ORDER BY host_name_long
"
$database          = "icmdb_prod"
$server            = "tripwire-prod.oa.caiso.com"
$now = Get-Date
"$now get cca list"

$ccalistcurrent    = Read-MSSQLDBData -command $command -database $database -server $server

$now = Get-Date
"$now nodes that are cca"

#Nodes that are CCA
$nodeslistcca = $nodeslist | Where-Object { $_.tags.tag -eq 'CCA'}

#Nodes that are MCA
#$nodeslistmca = $nodeslist | Where-Object { $_.tags.tag -eq 'MCA' }

$now = Get-Date
"$now latest version for each cca"

#collect latest version for each cca
$latestversionrequiredbaselinelist = $null
foreach($cca in $nodeslistcca)
{
    $st                                 = Get-Date
    $ccan                               = $cca.name
    $nodeId                             = $cca.id
    $now = Get-Date
    "$now $ccan version list"
    #if ($ccan -ne "FTRIPWIREP05.oa.caiso.com" )
    #{
        $latestversionlist                  = Get-iTripwireLatestVersionList -websession $websession -nodeId $nodeId -ruleId $ruleslistids
         $now = Get-Date
        "$now $ccan version list collected"

        #$latestversionlistrequiredbaseline  = $latestversionlist | Where-Object { $ruleslistrequiredbaselineids -match $_.ruleId}
        #$latestversionrequiredbaselinelist += $latestversionlistrequiredbaseline
        $latestversionrequiredbaselinelist += $latestversionlist
    #}
    $sp                                 = Get-Date
    $tm                                 = (New-TimeSpan -Start $st -End $sp).TotalMinutes
    "$ccan minutes to process: $tm"

}
$now = Get-Date

$directory    = "D:\share\"
$filenametime = (Get-Date).ToString("yyyyMMddHHmm")
$filename     = ($directory + $filenametime + "_required_baseline_results.csv").ToLower()

$latestversionrequiredbaselinelist | Where-Object {$_.ruleName -ne 'VMware ESX Hypervisor API Properties' -or $_.elementname -match 'HostSystem.summary.config.product' } | select nodeName, rulename, timeDetected -unique | select nodeName, ruleName, timeDetected, @{Name='baselineneeded'; expression={if (([datetime]($_.timeDetected) -$now).TotalDays -lt -20) { $true } else { $false }} } | Export-csv $filename -NoTypeInformation