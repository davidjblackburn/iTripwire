# Looks up ILO device types in Tripwire, query their URL for OS info, update an External rule

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

$systemname               = "tripwire-prod.company.com"
$username                 = "tripwireuser"
$password                 = "tripwirepassword"
$hash                     = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($username+":"+$password))

$websession               = Get-iTripwireLoginWebsession -hash $hash -systemname $systemname
$nodes                    = Get-iTripwireNodesList -websession $websession -systemname $systemname
$ilolist                  = $nodes | Where-Object {$_.type -eq "ILO"}

$rules                    = Get-iTripwireRulesList -websession $websession -systemname $systemname
$osversionrule            = $rules | Where-Object {$_.name -eq 'OSVERSION (ILO)' -and $_.type -eq 'Command Output Validation Rule'}
$osversionruleid          = $osversionrule.id

$nodeslist                = $nodes

$ilolist                  = $nodeslist | Where-Object {$_.type -eq "ILO"}
$ruleslist                = Get-iTripwireRulesList -websession $websession -systemname $systemname

$rulename                 = "OSVERSION (ILO)"
$elementname              = "ilo-os-version"

$ruleider                 = ($ruleslist | Where-Object {$_.name -like $rulename -and $_.type -eq "External Rule"}).id

foreach ($ilo in $ilolist) 
{

    $now                      = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
    $iloname                  = $ilo.name
    $nodeId                   = ($ilolist -match $iloname).id
    $iloname
    $noosversion              = $true

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

    if ($noosversion)
    {
        $osversion = "url not responding"
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
        $result                    = Set-iTripwireExternalRuleContent -completiontime $now -content $osversionfinal -creationtime $now -elementname $elementname -nodeid $nodeid -ruleid $ruleider -timedetected $now -websession $websession -severity_v 777 -systemname $systemname
    }
    catch
    {
        $message                   = "Check of node '$iloname' rule '$rulename' element '$elementname' failure"
    }

    Set-iTripwireLogMessages -websession $websession -objects $objects -message $message -systemname $systemname

    $osversion                = $null

}

return
