Function Get-iTripwireLoginWebsession
{
param (
    [string]$username    = "",
    [string]$password    = "",
    [string]$hash        = "Basic dHJpcHdpcmU6NkdOJXk3WlBMciFEWXVjI0VLaEE=",
    [string]$systemname  = "tripwire-prod.oa.caiso.com",
    [string]$logserver   = "tripwire-prod.oa.caiso.com",
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

if ($username -ne "" -and $password -ne "")
{
    $hash           = "Basic " + [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($username+":"+$password))
}

if ($hash -eq $null)
{
    if ( $severity -ge 6 )
    {
        $syslog_Array.msg        = "Need to specific Basic -has or -username and -password"
        $syslog_Array.timestamp  = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ")

        Write-SyslogArr $syslog_Array
    }
    return
}


$headers         = @{"Accept"="application/json";"Content-Type"="application/json";"X-Requested-With"="TE-REST-API";"Authorization"="$hash"}
$uri             = "https://$systemname/api/v1/csrf-token"
$tokenresponse   = Invoke-RestMethod -Uri $uri -Method Get -headers $headers -SessionVariable websession -MaximumRedirection 0
$token           = $tokenresponse.tokenvalue
$headers         = @{"CSRFToken"="$token"}
$uri             = "https://$systemname/api/v1/status"
$result          = Invoke-RestMethod -Uri $uri -Method Get -headers $headers -WebSession $websession
return $websession

}
