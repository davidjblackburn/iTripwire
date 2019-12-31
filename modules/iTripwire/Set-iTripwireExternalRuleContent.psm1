Function Set-iTripwireExternalRuleContent
{
param (
    $websession             = "",
    [string]$systemname      = "tripwire-prod.company.com"      # Use the Tripwire server name.
    [string]$nodeid         = "",
    [string]$ruleid         = "",
    [string]$elementname    = "test-test",
    [string]$content        = $null,
    [string]$contentbase64  = $null,
    [string]$exists         = "true",
    [string]$severity_v     = "0",
    [string]$timedetected   = "2018-05-25T22:01:24.772Z",
    [string]$creationtime   = "2018-05-25T22:01:24.772Z",
    [string]$completiontime = "2018-05-25T22:01:24.772Z"
    )

$headerplaintext             = @{"Accept"="text/plain"}
$headerappjson               = @{"Accept"="application/json"}

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

if ($content -ne "" -and $contentbase64 -ne "")
{ 

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
