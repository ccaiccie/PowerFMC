function New-FMCAuthToken {
<#
 .SYNOPSIS
Obtains Domain UUID and X-auth-access-token
 .DESCRIPTION
This cmdlet will invoke a REST post against the FMC API, authenticate, and provide an X-auth-access-token and
Domain UUID for use in other functions
 .EXAMPLE
# New-FMCAuthToken -fmcHost 'https://fmcrestapisandbox.cisco.com' -username 'davdecke' -password 'YDgQ7CBR'
 .PARAMETER fmcHost
Base URL of FMC
 .PARAMETER username
REST account username
 .PARAMETER password
REST account password
/#>
    param
    (
        [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
            [string]$FMCHost='https://fmcrestapisandbox.cisco.com',
        [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
            [string]$username='davdecke',
        [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
            [string]$password='EZnFnvCd'
    )
Begin {
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
[System.Net.ServicePointManager]::SecurityProtocol = 'Tls12'
     }
Process {
$credPair = "$($username):$($password)"
$encodedCredentials = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($credPair))
$uri = "$FMCHost/api/fmc_platform/v1/auth/generatetoken"
$headers = @{ Authorization = "Basic $encodedCredentials" }
$AuthResponse = Invoke-WebRequest -Uri $uri -Headers $headers -Method Post
$Domain =  $AuthResponse.Headers.Item('DOMAIN_UUID')
$AuthAccessToken = $AuthResponse.Headers.Item('X-auth-access-token')
        }
End {
$output = New-Object -TypeName psobject
$output | Add-Member -MemberType NoteProperty -Name fmcHost          -Value $FMCHost
$output | Add-Member -MemberType NoteProperty -Name Domain          -Value $Domain
$output | Add-Member -MemberType NoteProperty -Name AuthAccessToken -Value $AuthAccessToken
$output
    }
}
function Get-FMCNetworkObjects {
<#
 .SYNOPSIS
Displays network objects in FMC
 .DESCRIPTION
This cmdlet will invoke a REST request against the FMC API and retrieve items under /object/networks
 .EXAMPLE
# Get-FMCNetworkObjects -fmcHost "https://fmcrestapisandbox.cisco.com" -username 'davdecke' -password 'xxxxxx'
 .PARAMETER fmcHost
Base URL of FMC
 .PARAMETER AuthAccessToken
X-auth-accesss-token 
 .PARAMETER Domain
Domain UUID 
/#>
    param
    (
        [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
            [string]$Name="*",
        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
            [string]$FMCHost,
        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
            [string]$AuthAccessToken,
        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
            [string]$Domain,
        [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$false)]
            [switch]$Terse
    )
Begin {
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
[System.Net.ServicePointManager]::SecurityProtocol = 'Tls12'
      }
Process {
 $uri         = "$FMCHost/api/fmc_config/v1/domain/$Domain/object/networks?offset=0&limit=25"
 $headers     = @{ "X-auth-access-token" = "$AuthAccessToken" }
 $response    = Invoke-RestMethod -Method Get -Uri $uri -Headers $headers
 [int]$pages  = $response.paging.pages
 [int]$offset = 0
 $items       = $response.items
 while ($pages -gt 1) {
    [int]$offset = $offset+25
    $uri         = "$FMCHost/api/fmc_config/v1/domain/$Domain/object/networks?offset=$offset&limit=25"
    $response    = Invoke-RestMethod -Method Get -Uri $uri -Headers $headers
    $items      += $response.items
    $pages--
                      }
if ($Terse.IsPresent) {
        $NetObjects = @()
        $NetObjects = $items
                      } else {
 $NetObjects = @()
 $items      = $items | Where-Object {$_.name -like $Name}
 $items.links.self | foreach {
    $response    = Invoke-RestMethod -Method Get -Uri "$_" -Headers $headers
    $NetObjects += $response
                             }
                            }
        }
End {
$NetObjects 
    }
}
function New-FMCNetworkObject {
<#
 .SYNOPSIS
Create network objects in FMC
 .DESCRIPTION
This cmdlet will invoke a REST request against the FMC API and retrieve items under /object/networks
 .EXAMPLE
# $FMCHost = 'https://fmcrestapisandbox.cisco.com'
# $a = New-FMCAuthToken -fmcHost $FMCHost -username 'davdecke' -password 'xxxxxx'
# $a | New-FMCNetworkObject -fmcHost $FMCHost -name 'PowerFMC_172.21.33.0/24' -Network "172.21.33.0" -Prefix 24 -description "Test Object for PowerFMC 2"
 .PARAMETER fmcHost
Base URL of FMC
 .PARAMETER AuthAccessToken
X-auth-accesss-token 
 .PARAMETER Domain
Domain UUID 
 .PARAMETER name
Name of the rule. Illegal characters (/,\,whitespaces) are automatically replaced with underscrores 
 .PARAMETER Network
The network or host dotted-decimal IP
 .PARAMETER Prefix
Prefix length for network (32 for host)
/#>
    param
    (
        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
            [string]$Name,
        [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
            [string]$Description,
        [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
            [string]$Overridable="false",
        [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
        [ValidateSet("network","host","range")]
            [string]$type="network",
        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
            [string]$Network,
        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
            [string]$FMCHost,
        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
            [string]$Domain,
        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
            [string]$AuthAccessToken
    )
Begin {
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
[System.Net.ServicePointManager]::SecurityProtocol = 'Tls12'
        }
Process {
$uri = "$FMCHost/api/fmc_config/v1/domain/$Domain/object/networks"
$headers = @{ "X-auth-access-token" = "$AuthAccessToken" ;'Content-Type' = 'application/json' }
$Name = $Name -replace '(\\|\/|\s)','_'
$body = New-Object -TypeName psobject
$body | Add-Member -MemberType NoteProperty -name name        -Value $Name
$body | Add-Member -MemberType NoteProperty -name value       -Value "$Network"
$body | Add-Member -MemberType NoteProperty -name overridable -Value $Overridable
$body | Add-Member -MemberType NoteProperty -name description -Value "$Description"
$body | Add-Member -MemberType NoteProperty -name type        -Value $type
 
$response = Invoke-RestMethod -Method Post -Uri $uri -Headers $headers -Body ($body | ConvertTo-Json)
$response
        }
End {}
}
function Get-FMCNetworkGroups {
<#
 .SYNOPSIS
Displays network groups in FMC
 .DESCRIPTION
This cmdlet will invoke a REST request against the FMC API and retrieve items under /object/networkgroups
 .EXAMPLE
# Get-FMCNetworkObjects -fmcHost "https://fmcrestapisandbox.cisco.com" -AuthAccessToken 'e276abec-e0f2-11e3-8169-6d9ed49b625f' -Domain '618846ea-6e3e-4d69-8f30-55f31b52ca3e'
 .PARAMETER fmcHost
Base URL of FMC
 .PARAMETER AuthAccessToken
X-auth-accesss-token 
 .PARAMETER Domain
Domain UUID 
/#>
    param
    (
        [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
            [string]$Name="*",
        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
            [string]$FMCHost,
        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
            [string]$AuthAccessToken,
        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
            [string]$Domain
    )
Begin {
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
[System.Net.ServicePointManager]::SecurityProtocol = 'Tls12'
      }
Process {
 $uri         = "$FMCHost/api/fmc_config/v1/domain/$Domain/object/networkgroups?offset=0&limit=25"
 $headers     = @{ "X-auth-access-token" = "$AuthAccessToken" }
 $response    = Invoke-RestMethod -Method Get -Uri $uri -Headers $headers
 [int]$pages  = $response.paging.pages
 [int]$offset = 0
 $items       = $response.items
 while ($pages -gt 1) {
    [int]$offset = $offset+25
    $uri         = "$FMCHost/api/fmc_config/v1/domain/$Domain/object/networkgroups?offset=$offset&limit=25"
    $response    = Invoke-RestMethod -Method Get -Uri $uri -Headers $headers
    $items      += $response.items
    $pages--
                      }
 $NetObjects = @()
 $items      = $items | Where-Object {$_.name -like $Name}
 $items.links.self | foreach {
    $response    = Invoke-RestMethod -Method Get -Uri "$_" -Headers $headers
    $NetObjects += $response
                             }

        }
End {
$NetObjects 
    }
}
function New-FMCNetworkGroup {
<#
 .SYNOPSIS
Create network groups in FMC
 .DESCRIPTION
This cmdlet will invoke a REST request against the FMC API and create Network Groups
 .EXAMPLE
# $FMCHost = 'https://fmcrestapisandbox.cisco.com'
# $a = New-FMCAuthToken -fmcHost $FMCHost -username 'davdecke' -password 'xxxxxx'
# $a | New-FMCNetworkGroup -fmcHost $FMCHost -name 'PowerFMC_TestGroup' -members 'PowerFMC_TestObj1,PowerFMC_TestObj2,PowerFMC_TestObj3' -description "Group for PowerFMC"
 .PARAMETER fmcHost
Base URL of FMC
 .PARAMETER AuthAccessToken
X-auth-accesss-token 
 .PARAMETER Domain
Domain UUID 
 .PARAMETER name
Name of the rule. Illegal characters (/,\,whitespaces) are automatically replaced with underscrores 
 .PARAMETER Network
The network or host dotted-decimal IP
 .PARAMETER Prefix
Prefix length for network (32 for host)
/#>
    param
    (
        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
            [string]$Name,
        [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
            [string]$Members,
        [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
            [string]$Prefixes,
        [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
            [string]$Description,
        [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
            [string]$Overridable="false",
        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
            [string]$FMCHost,
        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
            [string]$Domain,
        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
            [string]$AuthAccessToken
    )
Begin {
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
[System.Net.ServicePointManager]::SecurityProtocol = 'Tls12'
        }
Process {
$uri = "$FMCHost/api/fmc_config/v1/domain/$Domain/object/networkgroups"
$headers = @{ "X-auth-access-token" = "$AuthAccessToken" ;'Content-Type' = 'application/json' }
$Name = $Name -replace '(\\|\/|\s)','_'

$MemberArray = $Members -split ','
$NetworkObjects = Get-FMCNetworkObjects -fmcHost $FMCHost -AuthAccessToken $AuthAccessToken -Domain $Domain -Terse
$objects = @()
$MemberArray | foreach {
            $NetworkObject = $NetworkObjects | Where-Object -Property name -EQ $_
            $id = $NetworkObject.id
            $object = New-Object psobject
            $object | Add-Member -MemberType NoteProperty -Name id -Value $id
            $objects += $object
                   }

$Prefixes = $Prefixes -split ','
$literals = @()
$Prefixes | foreach {
             $literal = New-Object psobject
             $literal | Add-Member -MemberType NoteProperty -Name value -Value $_
             $literals += $literal
                    }
$body = New-Object -TypeName psobject
$body | Add-Member -MemberType NoteProperty -name type        -Value "NetworkGroup"
if ($Members) {$body | Add-Member -MemberType NoteProperty -name objects  -Value $objects}
if ($Prefixes){$body | Add-Member -MemberType NoteProperty -name literals -Value $literals}
$body | Add-Member -MemberType NoteProperty -name overridable -Value $Overridable
$body | Add-Member -MemberType NoteProperty -name description -Value "$Description"
$body | Add-Member -MemberType NoteProperty -name name        -Value "$Name"
$response = Invoke-RestMethod -Method Post -Uri $uri -Headers $headers -Body ($body | ConvertTo-Json)
$response
        }
End {}
}
function Get-FMCObject {
    param
    (
        [Parameter(Mandatory=$true, ValueFromPipeline=$true)]
            [string]$uri,
        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
            [string]$AuthAccessToken
    )
Begin   {
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
[System.Net.ServicePointManager]::SecurityProtocol = 'Tls12'
         }
Process {
$headers = @{ "X-auth-access-token" = "$AuthAccessToken" }
$response = Invoke-RestMethod -Method Get -Uri $uri -Headers $headers
        }
End     {
$response
        }
}
function Remove-FMCObject {
    param
    (
        [Parameter(Mandatory=$true, ValueFromPipeline=$true)]
            [string]$uri,
        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
            [string]$AuthAccessToken
    )
Begin   {
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
[System.Net.ServicePointManager]::SecurityProtocol = 'Tls12'
         }
Process {
$headers = @{ "X-auth-access-token" = "$AuthAccessToken" }
$response = Invoke-RestMethod -Method Delete -Uri $uri -Headers $headers
$response
        }
End {}
}
function New-FMCObject {
    param
    (
        [Parameter(Mandatory=$true, ValueFromPipeline=$true)]
            [string]$uri,
        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
            [string]$object,
        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
            [string]$AuthAccessToken
    )
Begin   {
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
[System.Net.ServicePointManager]::SecurityProtocol = 'Tls12'
         }
Process {
$headers = @{ "X-auth-access-token" = "$AuthAccessToken" ;'Content-Type' = 'application/json' }
$response = Invoke-RestMethod -Method Post -Uri $uri -Headers $headers -Body $object
        }
End     {
$response
        }
}
function Get-FMCPortObject {
    param
    (
        [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
            [string]$Name="*",
        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
            [string]$FMCHost,
        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
            [string]$Domain,
        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
            [string]$AuthAccessToken
    )
Begin   {
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
[System.Net.ServicePointManager]::SecurityProtocol = 'Tls12'
        }
Process {
$uri     = "$FMCHost/api/fmc_config/v1/domain/$Domain/object/protocolportobjects"
$headers = @{ "X-auth-access-token" = "$AuthAccessToken" }
$response = Invoke-RestMethod -Method Get -Uri $uri -Headers $headers
$pages = $response.paging.pages
$items = $response.items
$offset = 0
while ($pages -gt 1) {
    $offset   = $offset+25
    $pages--
    $uri      = "$FMCHost/api/fmc_config/v1/domain/$Domain/object/protocolportobjects?offset=$offset&limit=25"
    $response = Invoke-RestMethod -Method Get -Uri $uri -Headers $headers
    $items   += $response.items
                     }
$response = @()
$items = $items | Where-Object {$_.name -like $Name}
$items.links.self | foreach {
    $response += Invoke-RestMethod -Method Get -Uri $_ -Headers $headers
                            }
$uri     = "$FMCHost/api/fmc_config/v1/domain/$Domain/object/icmpv4objects"
$response_icmp = Invoke-RestMethod -Method Get -Uri $uri -Headers $headers
$pages = $response_icmp.paging.pages
$items = $response_icmp.items
$offset = 0
while ($pages -gt 1) {
    $offset   = $offset+25
    $pages--
    $uri      = "$FMCHost/api/fmc_config/v1/domain/$Domain/object/icmpv4objects?offset=$offset&limit=25"
    $response_icmp = Invoke-RestMethod -Method Get -Uri $uri -Headers $headers
    $items   += $response.items
                     }
$response_icmp = @()
$items = $items | Where-Object {$_.name -like $Name}
$items.links.self | foreach {
    $response_icmp += Invoke-RestMethod -Method Get -Uri $_ -Headers $headers
                            }
        }
End     {
$response
$response_icmp
        }
}
function New-FMCPortObject {
    param
    (
        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
            [string]$Name,
        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
            [string]$protocol,
        [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
            [string]$port,
        [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
            [string]$Description,
        [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
            [string]$Overridable="false",
        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
            [string]$FMCHost,
        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
            [string]$Domain,
        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
            [string]$AuthAccessToken
    )
Begin   {
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
[System.Net.ServicePointManager]::SecurityProtocol = 'Tls12'
        }
Process {
$uri     = "$FMCHost/api/fmc_config/v1/domain/$Domain/object/protocolportobjects"
$headers = @{ "X-auth-access-token" = "$AuthAccessToken" ;'Content-Type' = 'application/json' }
$Name    = $Name -replace '(\\|\/|\s)','_'
$body    = New-Object -TypeName psobject
$body | Add-Member -MemberType NoteProperty -name type        -Value "ProtocolPortObject"
$body | Add-Member -MemberType NoteProperty -name port        -Value "$port"
$body | Add-Member -MemberType NoteProperty -name protocol    -Value "$protocol"
$body | Add-Member -MemberType NoteProperty -name description -Value "$Description"
$body | Add-Member -MemberType NoteProperty -name name        -Value "$Name"
$response = Invoke-RestMethod -Method Post -Uri $uri -Headers $headers -Body ($body | ConvertTo-Json)
$response
        }
End     {}
}
function New-FMCPortGroup {
    param
    (
        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
            [string]$Name,
        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
            [string]$protocol,
        [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
            [string]$port,
        [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
            [string]$Description,
        [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
            [string]$Overridable="false",
        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
            [string]$FMCHost,
        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
            [string]$Domain,
        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
            [string]$AuthAccessToken
    )
Begin   {
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
[System.Net.ServicePointManager]::SecurityProtocol = 'Tls12'
        }
Process {
$uri     = "$FMCHost/api/fmc_config/v1/domain/$Domain/object/protocolportobjects"
$headers = @{ "X-auth-access-token" = "$AuthAccessToken" ;'Content-Type' = 'application/json' }
$Name    = $Name -replace '(\\|\/|\s)','_'
$body    = New-Object -TypeName psobject
$body | Add-Member -MemberType NoteProperty -name type        -Value "ProtocolPortObject"
$body | Add-Member -MemberType NoteProperty -name port        -Value "$port"
$body | Add-Member -MemberType NoteProperty -name protocol    -Value "$protocol"
$body | Add-Member -MemberType NoteProperty -name description -Value "$Description"
$body | Add-Member -MemberType NoteProperty -name name        -Value "$Name"
$response = Invoke-RestMethod -Method Post -Uri $uri -Headers $headers -Body ($body | ConvertTo-Json)
$response
        }
End     {}
}
