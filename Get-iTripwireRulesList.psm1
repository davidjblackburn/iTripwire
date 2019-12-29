Function Get-iTripwireRulesList
{
param (
    $websession,
    [string]$systemname  = "tripwire-prod.oa.caiso.com",
    [string]$logserver   = "tripwire-prod.oa.caiso.com",
    [int]$pagelimit      = 100,
    [string]$isdisabled  = "false",
    [string]$auditenabled= "true",
    [string]$logdatabase = "infosecrisks_prod",
    [string]$logtable    = "InfoSecRisksLog",
    [switch]$logtoout    = $true,
    [switch]$logtoserver = $false,
    [int]$severity       = 6
    )
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

$jsonserial               = New-Object -TypeName System.Web.Script.Serialization.JavaScriptSerializer
$jsonserial.MaxJsonLength = [int]::MaxValue
$ruleslist                = $null

$uri                      = "https://$systemname/api/v1/rules"

$ruleslist                = Invoke-RestMethod -uri $uri -Method get -WebSession $websession
#$nodeslist_obj            = $jsonserial.Deserialize($nodes,[System.Object])

#get types
#$types = @()

#foreach ($node in $nodeslist_obj)
#{
#    $type             = $node.type
#    $types           += $type
#}

#$typelist = $types | Select-Object -Unique

#foreach ($type in $typelist)
#{
#    $uri             = "https://$systemname/api/v1/nodes?pageLimit=$pagelimit&type=$type"
#    $nodes           = Invoke-RestMethod -uri $uri -Method get -WebSession $websession
#    $nodeslist      += $nodes

#    $page            = 0
#    do
#    {
#        $page           += $pagelimit
#        $uri             = "https://$systemname/api/v1/nodes?pageLimit=$pagelimit&pageStart=$page&type=$type"
#        $nodes           = Invoke-RestMethod -uri $uri -Method get -WebSession $websession
#        $nodeslist      += $nodes

#    } while ($nodes.count -eq $pagelimit)
#}

return $ruleslist

}
