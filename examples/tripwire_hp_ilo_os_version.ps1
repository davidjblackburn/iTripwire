clear

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
#[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls

$systemname               = "tripwire-prod.company.com"
$websession               = Get-iTripwireLoginWebsession -hash $hash -systemname $systemname
$nodes                    = Get-iTripwireNodesList -websession $websession -systemname $systemname
$ilolist                  = $nodes | Where-Object {$_.type -eq "ILO"}

$rules                    = Get-iTripwireRulesList -websession $websession  -systemname $systemname
$osversionrule            = $rules | Where-Object {$_.name -eq 'OSVERSION (ILO)' -and $_.type -eq 'Command Output Validation Rule'}
$osversionruleid          = $osversionrule.id


$nodeslist                = $nodes
#$ccalist                  = $nodeslist | Where-Object {$_.tags -match "CCA" }
#$ccailolist               = $nodeslist | Where-Object {$_.type -eq "ILO" -and $_.tags -match "CCA"}
$ilolist                   = $nodeslist | Where-Object {$_.type -eq "ILO"}
$ruleslist                = Get-iTripwireRulesList -websession $websession

#[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls11

$rulename                 = "OSVERSION (ILO)"
$elementname              = "ilo-os-version"

$ruleider                 = ($ruleslist | Where-Object {$_.name -like $rulename -and $_.type -eq "External Rule"}).id
$ruleidcovr               = ($ruleslist | Where-Object {$_.name -like $rulename -and $_.type -eq "Command Output Validation Rule"}).id
<#
$needattestation          = @(
                             "ilo-fpapidm1.oa.caiso.com"
                            ,"ilo-fprdas1.oa.caiso.com"
                            ,"ilo-fpras1.oa.caiso.com"
                            ,"ilo-apras1.oa.caiso.com"
                            ,"ilo-fprdas3.oa.caiso.com"
                            ,"ilo-apras2.oa.caiso.com"
                            ,"ilo-fpapomt465.oa.caiso.com"
                            ,"ilo-aprdas1.oa.caiso.com"
                            ,"ilo-fpras2.oa.caiso.com"
                            ,"ilo-aprdas2.oa.caiso.com"
                            ,"ilo-fprdas2.oa.caiso.com"
                            ,"ilo-aprdas3.oa.caiso.com"
                            ,"ilo-fputadm3.oa.caiso.com"
                            ,"ilo-asqrdas1.oa.caiso.com"
                            )
#>
$attestdate                   = Get-Date
$attestdateyear               = $attestdate.Year.ToString()
$attestdatemonth              = $attestdate.Month.ToString()
$attestdateday                = $attestdate.Day

if ($attestdateday -lt 16) { $attestday = "0" }
if ($attestdateday -gt 15) { $attestday = "1" }

$attestperiod                 = $attestdateyear + $attestdatemonth + $attestday

foreach ($ilo in $ilolist) 
{

    $now                      = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
    $iloname                  = $ilo.name
    $nodeId                   = ($ilolist -match $iloname).id
    $iloname
    $noosversion              = $true

    #Check if ILO is known to need attestation
    switch ($iloname)
    {
        "ilo-fpapidm1.oa.caiso.com"
        {
            $osversion                = $iloname + " ILO 3 1.88 " + $attestperiod
            $collector                = "manual"
            $noosversion              = $false
            break
        }
        "ilo-fprdas4.oa.caiso.com"
        {
            $osversion                = $iloname + " ILO 2 ROM A 04.04, ROM B 04.11, Boot ROM B " + $attestperiod
            $collector                = "manual"
            $noosversion              = $false
            break
        }
        "ilo-fpras1.oa.caiso.com"
        {
            $osversion                = $iloname + " Sun Blade 6000 ILOM ROM A 04.04, ROM B 04.11, Boot ROM B " + $attestperiod
            $collector                = "manual"
            $noosversion              = $false
            break
        }
        "ilo-apras1.oa.caiso.com"
        {
            $osversion                = $iloname + " ILO 2 ROM A 04.04, ROM B 04.11, Boot ROM B " + $attestperiod
            $collector                = "manual"
            $noosversion              = $false
            break
        }
        "ilo-fprdas3.oa.caiso.com"
        {
            $osversion                = $iloname + " ILO 2 ROM A 04.04, ROM B 04.11, Boot ROM B " + $attestperiod
            $collector                = "manual"
            $noosversion              = $false
            break
        }
        "ilo-apras2.oa.caiso.com"
        {
            $osversion                = $iloname + " Sun Blade 6000 ILOM ROM A 04.04, ROM B 04.11, Boot ROM B " + $attestperiod
            $collector                = "manual"
            $noosversion              = $false
            break
        }
        "ilo-fpapomt465.oa.caiso.com"
        {
            $osversion                = $iloname + " Sun Blade 6000 ILOM ROM A 04.04, ROM B 04.11, Boot ROM B " + $attestperiod
            $collector                = "manual"
            $noosversion              = $false
            break
        }
        "ilo-aprdas1.oa.caiso.com"
        {
            $osversion                = $iloname + " iLO 2 ROM A 04.04, ROM B 04.11, Boot ROM B " + $attestperiod
            $collector                = "manual"
            $noosversion              = $false
            break
        }
        "ilo-fpras2.oa.caiso.com"
        {
            $osversion                = $iloname + " iLO 2 ROM A 04.04, ROM B 04.11, Boot ROM B " + $attestperiod
            $collector                = "manual"
            $noosversion              = $false
            break
        }
        "ilo-aprdas2.oa.caiso.com"
        {
            $osversion                = $iloname + " iLO 2 ROM A 04.04, ROM B 04.11, Boot ROM B " + $attestperiod
            $collector                = "manual"
            $noosversion              = $false
            break
        }
        "ilo-fprdas2.oa.caiso.com"
        {
            $osversion                = $iloname + " iLO 2 ROM A 04.04, ROM B 04.11, Boot ROM B " + $attestperiod
            $collector                = "manual"
            $noosversion              = $false
            break
        }
        "ilo-aprdas3.oa.caiso.com"
        {
            $osversion                = $iloname + " iLO 2 v3.0.12.11.fr84322 " + $attestperiod
            $collector                = "manual"
            $noosversion              = $false
            break
        }
        "ilo-fputadm3.oa.caiso.com"
        {
            $osversion                = $iloname + " Sun Integrated LOM 3.0.6.13.e " + $attestperiod
            $collector                = "manual"
            $noosversion              = $false
            break
        }
        "ilo-asqrdas1.oa.caiso.com"
        {
            $osversion                = $iloname + " ILO 2 ROM A 04.04, ROM B 04.11, Boot ROM B " + $attestperiod
            $collector                = "manual"
            $noosversion              = $false
            break
        }
    }


    #Check if ILO is labeled as broken
    $broken                   = $ilo -match "Broken"
    if ($broken)
    {
        $osversion                = "Broken"
        $collector                = $null
        $noosversion              = $false
    }

    #check ADDM
    if ($noosversion)
    {
        $iloinfo                  = $ilodata | Where-Object {$_.ip_address -eq $ilo.ipAddresses[0]}
       #$rfiloinfo                = $rfilodata | Where-Object {$_.BMCServiceDesk__HostName__c -eq $ilo.name}
        $osversion                = ($iloinfo.model + " " + $iloinfo.os_version + " " + $iloinfo.firmware_version) -replace " none"
        $osversionlen             = ($osversion -replace " ").length
        if ($osversionlen -gt 2)
        {
            $collector                = "addm"
            $noosversion              = $false
        }
    }

    #Check URL query
    if ($noosversion)
    {
        $os                       = $null
        $version                  = $null
        $url                      = "https://$iloname/xmldata?item=All"
        try
        {
            [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls
            [xml]$results             = Invoke-WebRequest -Uri $url
            [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        }
        catch
        {
            $osversion               = $null
        }
        if ($osversion -ne $null)
        {
            $os                       = $results.RIMP.MP.PN
            $version                  = $results.RIMP.MP.fwri
            $osversion                = "$os $version"
            $osversionlen             = ($osversion -replace " ").length
            if ($osversionlen -gt 2)
            {
                $collector                = "url"
                $noosversion              = $false
            }
        }
    }

    #Check tripwire query
    if ($noosversion)
    {
  
        #$nodeId                   = ($nodes | Where-Object { $_.name -eq $iloname }).id
        #$osversionelementid       = (Get-iTripwireLatestVersionList -websession $websession -nodeId $nodeId | Where-Object {$_.ruleId -eq $ruleidcovr}).id
        $osversionelementid       = (Get-iTripwireLatestVersionList -websession $websession -nodeId $nodeId -ruleId $ruleidcovr).id | Unique
        if ($osversionelementid -ne $null)
        {
            $result                   = Get-iTripwireVersionElementContent -websession $websession -elementid $osversionelementid
            $result_arr               = $result.Split("`n")

            $os                       = ($result_arr -match "name=" | Select-Object -Unique) -replace "    name=" -replace "`n"
            $version                  = ($result_arr -match "version=" | Select-Object -Unique) -replace "    version=" -replace "`n"
            $osversion                = "$os $version"
            $osversionlen             = ($osversion -replace " ").length
            if ($osversionlen -gt 2)
            {
                $collector                = "tripwire"
                $noosversion              = $false
            }
        }
     }

    if ($noosversion)
    {
        $osversion = "not in addm, tripwire, and url not responding"
        $collector = $null
    }
    
    $osversionfinal            =  "$osversion $collector"

    try
    {
        $message                   = "Check of node '$iloname' rule '$rulename' element '$elementname' success"
        $objects                   = $null
        $objects                   = @()
        $objects                   += $nodeid
        $objects                   += $ruleider
        #$objects                  += $elementname
        $result                    = Set-iTripwireExternalRuleContent -completiontime $now -content $osversionfinal -creationtime $now -elementname $elementname -nodeid $nodeid -ruleid $ruleider -timedetected $now -websession $websession -severity_v 777
    }
    catch
    {
        $message                   = "Check of node '$iloname' rule '$rulename' element '$elementname' failure"
    }

    Set-iTripwireLogMessages -websession $websession -objects $objects -message $message

    #$osversionfinal

    #$ilo.name
    #$results.requestData.versions
    $osversion                = $null

}

return
