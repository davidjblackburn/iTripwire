Function Get-iTripwireNodesList
{
param (
    $websession,
    [string]$systemname  = "tripwire-prod.company.com", # Use the Tripwire server name.
    [int]$pagelimit      = 100,
    [string]$isdisabled  = "false",
    [string]$auditenabled= "true"
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

$jsonserial               = New-Object -TypeName System.Web.Script.Serialization.JavaScriptSerializer
$jsonserial.MaxJsonLength = [int]::MaxValue
$nodeslist                = $null

$uri                      = "https://$systemname/api/v1/nodes"

$nodes                    = Invoke-RestMethod -uri $uri -Method get -WebSession $websession -Headers $headerappjson

if (($nodes.GetType()).BaseType.Name -ne "Array" )
{
    $nodeslist_obj            = $jsonserial.Deserialize($nodes,[System.Object])
}
else
{
    $nodeslist_obj            = $nodes
}

#get types
$types = @()

foreach ($node in $nodeslist_obj)
{
    $type             = $node.type
    $types           += $type
}

$typelist = $types | Select-Object -Unique

foreach ($type in $typelist)
{
    $uri             = "https://$systemname/api/v1/nodes?pageLimit=$pagelimit&type=$type"
    $nodes           = Invoke-RestMethod -uri $uri -Method get -WebSession $websession -Headers $headerappjson
    $nodeslist      += $nodes

    $page            = 0
    do
    {
        $page           += $pagelimit
        $uri             = "https://$systemname/api/v1/nodes?pageLimit=$pagelimit&pageStart=$page&type=$type"
        $nodes           = Invoke-RestMethod -uri $uri -Method get -WebSession $websession -Headers $headerappjson
        $nodeslist      += $nodes

    } while ($nodes.count -eq $pagelimit)
}

return $nodeslist

}
