Function Set-iTripwireExternalRuleContent
{
param (
    $websession             = "",
    [string]$systemname     = "tripwire-prod.oa.caiso.com",
    [string]$logserver      = "tripwire-prod.oa.caiso.com",
    [string]$nodeid         = "ftripwirep05.oa.caiso.com",
    [string]$ruleid         = "",
    [string]$elementname    = "test-test",
    [string]$content        = $null,
    [string]$contentbase64  = $null,
    [string]$exists         = "true",
    [string]$severity_v     = "0",
    [string]$timedetected   = "2018-05-25T22:01:24.772Z",
    [string]$creationtime   = "2018-05-25T22:01:24.772Z",
    [string]$completiontime = "2018-05-25T22:01:24.772Z",
    [string]$logdatabase    = "infosecrisks_prod",
    [string]$logtable       = "InfoSecRisksLog",
    [switch]$logtoout       = $true,
    [switch]$logtoserver    = $false,
    [int]$severity          = 6
    )

$syslog_Array                = Set-SyslogArr
$headerplaintext             = @{"Accept"="text/plain"}
$headerappjson               = @{"Accept"="application/json"}

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

if ( $severity -ge 7 )
{
    $syslog_Array.msg        = "Start script."
    $syslog_Array.timestamp  = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ")

    Write-SyslogArr $syslog_Array
}

if ($content -ne "" -and $contentbase64 -ne "")
{ 
    if ( $severity -ge 7 )
    {
        $syslog_Array.msg        = "No content, exiting."
        $syslog_Array.timestamp  = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ")

        Write-SyslogArr $syslog_Array
    }
    return 
}

if ($content -ne "")
{
    $contentbytes  = [System.text.Encoding]::UTF8.GetBytes($content)
    $contentbase64 = [convert]::ToBase64String($contentbytes)
    <#
    $body = 
    "
    {

      ""id"": ""string"",
      ""requestData"": {
        ""nodeId"": ""$nodeid"",
        ""ruleId"": ""$ruleid"",
        ""versions"": [
          {
            ""elementName"": ""$elementname"",
            ""content"": ""$content"",
            ""exists"": $exists,
            ""severity"": $severity_v,
            ""timeDetected"": ""$timedetected""
          }
        ]
      },
      ""status"": ""string"",
      ""statusMessage"": [
        {}
      ],
      ""creationTime"": ""$creationtime"",
      ""completionTime"": ""$completiontime""
    }
    "
    #>
}

if ($contentbase64 -ne "")
{
    $body = 
    "
    {

      ""id"": ""string"",
      ""requestData"": {
        ""nodeId"": ""$nodeid"",
        ""ruleId"": ""$ruleid"",
        ""versions"": [
          {
            ""elementName"": ""$elementname"",
            ""contentBase64"": ""$contentbase64"",
            ""exists"": $exists,
            ""severity"": $severity_v,
            ""timeDetected"": ""$timedetected""
          }
        ]
      },
      ""status"": ""string"",
      ""statusMessage"": [
        {}
      ],
      ""creationTime"": ""$creationtime"",
      ""completionTime"": ""$completiontime""
    }
    "
}

$uri               = "https://$systemname/api/v1/versions/createVersionRequests"
$newversion        =  Invoke-RestMethod -headers $headerappjson -uri $uri -body $body -Method POST -WebSession $websession
$id                = $newversion.id
$status            = $newversion.status
$uri               = "https://$systemname/api/v1/versions/createVersionRequests/$id"

while ($status -ne "COMPLETED")
{
    $results = Invoke-RestMethod -uri $uri -Method GET -WebSession $websession
    $status  = $results.status
    start-sleep 1
}

$results

}
