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
$uri = "$FMCHost/api/fmc_config/v1/domain/$Domain/object/portobjectgroups"
$headers = @{ "X-auth-access-token" = "$AuthAccessToken" ;'Content-Type' = 'application/json' }
$Name = $Name -replace '(\\|\/|\s)','_'

$MemberArray = $Members -split ','
$PortObjects = Get-FMCPortObject -fmcHost $FMCHost -AuthAccessToken $AuthAccessToken -Domain $Domain -Terse
$objects = @()
$MemberArray | foreach {
            $PortObject = $PortObjects | Where-Object -Property name -EQ $_
            $id   = $PortObject.id
            $type = $PortObject.type
            $object = New-Object psobject
            $object | Add-Member -MemberType NoteProperty -Name type -Value $type
            $object | Add-Member -MemberType NoteProperty -Name id   -Value $id
            $objects += $object
                   }

$body = New-Object -TypeName psobject
$body | Add-Member -MemberType NoteProperty -name type        -Value "PortObjectGroup"
$body | Add-Member -MemberType NoteProperty -name objects     -Value $objects
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
if ($Terse) {$Expanded='false'} else {$Expanded='true'}
      }
Process {
 $uri         = "$FMCHost/api/fmc_config/v1/domain/$Domain/object/networks?offset=0&limit=25&expanded=$Expanded"
 $headers     = @{ "X-auth-access-token" = "$AuthAccessToken" }
 $response    = Invoke-RestMethod -Method Get -Uri $uri -Headers $headers
 [int]$pages  = $response.paging.pages
 [int]$offset = 0
 $items       = $response.items
 while ($pages -gt 1) {
    [int]$offset = $offset+25
    $uri         = "$FMCHost/api/fmc_config/v1/domain/$Domain/object/networks?offset=$offset&limit=25&expanded=$Expanded"
    $response    = Invoke-RestMethod -Method Get -Uri $uri -Headers $headers
    $items      += $response.items
    $pages--
                      }
$NetObjects      = $items | Where-Object {$_.name -like $Name}
        }
End {
$NetObjects 
    }
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
            [string]$Domain,
        [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
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
if ($Terse) {$Expanded='false'} else {$Expanded='true'}
      }
Process {
 $uri         = "$FMCHost/api/fmc_config/v1/domain/$Domain/object/networkgroups?offset=0&limit=25&expanded=$Expanded"
 $headers     = @{ "X-auth-access-token" = "$AuthAccessToken" }
 $response    = Invoke-RestMethod -Method Get -Uri $uri -Headers $headers
 [int]$pages  = $response.paging.pages
 [int]$offset = 0
 $items       = $response.items
 while ($pages -gt 1) {
    [int]$offset = $offset+25
    $uri         = "$FMCHost/api/fmc_config/v1/domain/$Domain/object/networkgroups?offset=$offset&limit=25&expanded=$Expanded"
    $response    = Invoke-RestMethod -Method Get -Uri $uri -Headers $headers
    $items      += $response.items
    $pages--
                      }
 $NetObjects      = $items | Where-Object {$_.name -like $Name}
        }
End {
$NetObjects 
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
            [string]$AuthAccessToken,
        [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$false)]
            [switch]$Terse
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
if ($Terse) {$Expanded='false'} else {$Expanded='true'}
        }
Process {
$offset = 0
$uri     = "$FMCHost/api/fmc_config/v1/domain/$Domain/object/protocolportobjects?offset=$offset&limit=25&expanded=$Expanded"
$headers = @{ "X-auth-access-token" = "$AuthAccessToken" }
$response = Invoke-RestMethod -Method Get -Uri $uri -Headers $headers
$pages = $response.paging.pages
$items = $response.items
while ($pages -gt 1) {
    $offset   = $offset+25
    $pages--
    $uri      = "$FMCHost/api/fmc_config/v1/domain/$Domain/object/protocolportobjects?offset=$offset&limit=25&expanded=$Expanded"
    $response = Invoke-RestMethod -Method Get -Uri $uri -Headers $headers
    $items   += $response.items
                     }
$response = @()
$offset = 0
$uri     = "$FMCHost/api/fmc_config/v1/domain/$Domain/object/icmpv4objects?offset=$offset&limit=25&expanded=$Expanded"
$response_icmp = Invoke-RestMethod -Method Get -Uri $uri -Headers $headers
$pages = $response_icmp.paging.pages
$items += $response_icmp.items
while ($pages -gt 1) {
    $offset   = $offset+25
    $pages--
    $uri      = "$FMCHost/api/fmc_config/v1/domain/$Domain/object/icmpv4objects?offset=$offset&limit=25&expanded=$Expanded"
    $response_icmp = Invoke-RestMethod -Method Get -Uri $uri -Headers $headers
    $items   += $response.items
                     }
$response_icmp = @()
$PortObj = $items | Where-Object {$_.name -like $Name}
        }
End {
$PortObj 
    }
}
function Get-FMCPortGroups {
<#
 .SYNOPSIS
Displays network groups in FMC
 .DESCRIPTION
This cmdlet will invoke a REST request against the FMC API and retrieve items under /object/portobjectgroups
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
            [string]$Domain,
        [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
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
if ($Terse) {$Expanded='false'} else {$Expanded='true'}
      }
Process {
 [int]$offset = 0
 $uri         = "$FMCHost/api/fmc_config/v1/domain/$Domain/object/portobjectgroups?offset=$offset&limit=25&expanded=$Expanded"
 $headers     = @{ "X-auth-access-token" = "$AuthAccessToken" }
 $response    = Invoke-RestMethod -Method Get -Uri $uri -Headers $headers
 [int]$pages  = $response.paging.pages
 [int]$offset = 0
 $items       = $response.items
 while ($pages -gt 1) {
    [int]$offset = $offset+25
    $uri         = "$FMCHost/api/fmc_config/v1/domain/$Domain/object/portobjectgroups?offset=$offset&limit=25&expanded=$Expanded"
    $response    = Invoke-RestMethod -Method Get -Uri $uri -Headers $headers
    $items      += $response.items
    $pages--
                      }
 $NetObjects     = $items | Where-Object {$_.name -like $Name}
        }
End {
$NetObjects 
    }
}
function Get-FMCAccessPolicies {
    param
    (
        [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
            [string]$Name="*",
        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
            [string]$AuthAccessToken,
        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
            [string]$FMCHost,
        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
            [string]$Domain,
        [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$false)]
            [switch]$Terse
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
if ($Terse) {$Expanded='false'} else {$Expanded='true'}
         }
Process {
$headers = @{ "X-auth-access-token" = "$AuthAccessToken" }
$uri     = "$FMCHost/api/fmc_config/v1/domain/$Domain/policy/accesspolicies?offset=0&limit=25&expanded=$Expanded"
$response = Invoke-RestMethod -Method Get -Uri $uri -Headers $headers
$pages = $response.paging.pages
$items = $response.items
$offset = 0
while ($pages -gt 1) {
    $offset   = $offset+25
    $pages--
    $uri      = "$FMCHost/api/fmc_config/v1/domain/$Domain/policy/accesspolicies?offset=$offset&limit=25&expanded=$Expanded"
    $response = Invoke-RestMethod -Method Get -Uri $uri -Headers $headers
    $items   += $response.items
                     }
$response = $items | Where-Object -Property name -Like $Name
        }
End     {
$response
        }
}
function Get-FMCIntrusionPolicies {
    param
    (
        [Parameter(Mandatory=$false, ValueFromPipeline=$false)]
            [string]$Name="*",
        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
            [string]$AuthAccessToken,
        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
            [string]$FMCHost,
        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
            [string]$Domain,
        [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$false)]
            [switch]$Terse
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
if ($Terse) {$Expanded='false'} else {$Expanded='true'}
         }
Process {
$headers = @{ "X-auth-access-token" = "$AuthAccessToken" }
$uri     = "$FMCHost/api/fmc_config/v1/domain/$Domain/policy/intrusionpolicies?offset=0&limit=25&expanded=$Expanded"
$response = Invoke-RestMethod -Method Get -Uri $uri -Headers $headers
$pages = $response.paging.pages
$items = $response.items
$offset = 0
while ($pages -gt 1) {
    $offset   = $offset+25
    $pages--
    $uri      = "$FMCHost/api/fmc_config/v1/domain/$Domain/policy/intrusionpolicies?offset=$offset&limit=25&expanded=$Expanded"
    $response = Invoke-RestMethod -Method Get -Uri $uri -Headers $headers
    $items   += $response.items
                     }
$response = $items | Where-Object -Property name -Like "$Name"
        }
End     {
$response
        }
}
function Get-FMCAccessPolicyRules {
    param
    (
        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
            [string]$AccessPolicy,
        [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
            [string]$RuleName="*",
        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
            [string]$AuthAccessToken,
        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
            [string]$FMCHost,
        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
            [string]$Domain,
        [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$false)]
            [switch]$Terse
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
if ($Terse) {$Expanded='false'} else {$Expanded='true'}
         }
Process {
$headers = @{ "X-auth-access-token" = "$AuthAccessToken" }
$ContainerUUID = Get-FMCAccessPolicies -Name $AccessPolicy -AuthAccessToken $AuthAccessToken -FMCHost $FMCHost -Domain $Domain -Terse
$ContainerUUID = $ContainerUUID.id
$uri     = "$FMCHost/api/fmc_config/v1/domain/$Domain/policy/accesspolicies/$ContainerUUID/accessrules?offset=0&limit=25&expanded=$Expanded"
$response = Invoke-RestMethod -Method Get -Uri $uri -Headers $headers
$pages = $response.paging.pages
$items = $response.items
$offset = 0
while ($pages -gt 1) {
    $offset   = $offset+25
    $pages--
    $uri      = "$FMCHost/api/fmc_config/v1/domain/$Domain/policy/accesspolicies/$ContainerUUID/accessrules?offset=$offset&limit=25&expanded=$Expanded"
    $response = Invoke-RestMethod -Method Get -Uri $uri -Headers $headers
    $items   += $response.items
                     }
$response = $items | Where-Object -Property name -Like $RuleName
        }
End     {
$response
        }
}
function Get-FMCZone {
    param
    (
        [Parameter(Mandatory=$false, ValueFromPipeline=$false)]
            [string]$Name="*",
        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
            [string]$AuthAccessToken,
        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
            [string]$FMCHost,
        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
            [string]$Domain,
        [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$false)]
            [switch]$Terse
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
if ($Terse) {$Expanded='false'} else {$Expanded='true'}
         }
Process {
$headers = @{ "X-auth-access-token" = "$AuthAccessToken" }
$uri     = "$FMCHost/api/fmc_config/v1/domain/$Domain/object/securityzones?offset=0&limit=25&expanded=$Expanded"
$response = Invoke-RestMethod -Method Get -Uri $uri -Headers $headers
$pages = $response.paging.pages
$items = $response.items
$offset = 0
while ($pages -gt 1) {
    $offset   = $offset+25
    $pages--
    $uri      = "$FMCHost/api/fmc_config/v1/domain/$Domain/object/securityzones?offset=$offset&limit=25&expanded=$Expanded"
    $response = Invoke-RestMethod -Method Get -Uri $uri -Headers $headers
    $items   += $response.items
                     }
$response = $items | Where-Object -Property name -Like "$Name"
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
function New-FMCAccessPolicy {
    param
    (
        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
            [string]$Name,
        [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
            [string]$Description,
        [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
            [string]$ParentPolicy,
        [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
            [string]$IntrusionPolicy="No Rules Active",
        [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
            [string]$LogBegin="false",
        [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
            [string]$LogEnd="true",
        [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
            [string]$SendEventsToFMC="true",
        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
            [string]$FMCHost,
        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
            [string]$AuthAccessToken,
        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
            [string]$Domain
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
$uri     = "$FMCHost/api/fmc_config/v1/domain/$Domain/policy/accesspolicies"
$headers = @{ "X-auth-access-token" = "$AuthAccessToken" ;'Content-Type' = 'application/json' }
$IPID = Get-FMCIntrusionPolicies -Name $IntrusionPolicy -AuthAccessToken $AuthAccessToken -FMCHost $FMCHost -Domain $Domain -Terse
$IP = New-Object -TypeName psobject
$IP | Add-Member -MemberType NoteProperty -name id -Value $IPID.id
$DefAct = New-Object -TypeName psobject
$DefAct | Add-Member -MemberType NoteProperty -name intrusionPolicy -Value $IP
$DefAct | Add-Member -MemberType NoteProperty -name type            -Value AccessPolicyDefaultAction
$DefAct | Add-Member -MemberType NoteProperty -name logBegin        -Value $LogBegin
$DefAct | Add-Member -MemberType NoteProperty -name logEnd          -Value $LogEnd
$DefAct | Add-Member -MemberType NoteProperty -name sendEventsToFMC -Value $SendEventsToFMC

$body = New-Object -TypeName psobject
if ($ParentPolicy) {
    $Parent = Get-FMCAccessPolicies -Name $ParentPolicy -AuthAccessToken $AuthAccessToken -Domain $Domain -FMCHost $FMCHost -Terse
    $ParentID = New-Object psobject
    $ParentID | Add-Member -MemberType NoteProperty -Name type -Value AccessPolicy
    $ParentID | Add-Member -MemberType NoteProperty -Name name -Value $Parent.name
    $ParentID | Add-Member -MemberType NoteProperty -Name id   -Value $Parent.id
    $metadata = New-Object psobject
    $metadata | Add-Member -MemberType NoteProperty -Name inherit      -Value $true
    $metadata | Add-Member -MemberType NoteProperty -Name parentPolicy -Value $ParentID
    $body     | Add-Member -MemberType NoteProperty -name metadata     -Value $metadata
    $type = 'AccessPolicy'
                   } else {$type = 'AccessPolicyDefaultAction'}
$body | Add-Member -MemberType NoteProperty -name type           -Value $type
$body | Add-Member -MemberType NoteProperty -name name           -Value "$Name"
$body | Add-Member -MemberType NoteProperty -name description    -Value "$Description"
$body | Add-Member -MemberType NoteProperty -name defaultAction  -Value $DefAct

$response = Invoke-RestMethod -Method Post -Uri $uri -Headers $headers -Body ($body | ConvertTo-Json)
        }
End     {

($body | ConvertTo-Json)
$response
        }
}
function New-FMCAccessPolicyRule {
    param
    (
        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
            [string]$Name,

        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
            [string]$AccessPolicy,

        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
        [ValidateSet("ALLOW","TRUST","MONITOR","BLOCK","BLOCK_RESET","BLOCK_INTERACTIVE","BLOCK_RESET_INTERACTIVE")] 
            [string]$Action,

        [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
            [string]$SourceZones,

        [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
            [string]$DestinationZones,

        [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
            [string]$SourceNetworks,

        [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
            [string]$DestinationNetworks,

        [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
            [string]$SourcePorts,

        [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
            [string]$DestinationPorts,

        [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
            [bool]$Enabled=$true,

        [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
            [string]$IntrusionPolicy,

        [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
            [bool]$LogBegin=$false,

        [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
            [bool]$LogEnd=$true,

        [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
            [bool]$SendEventsToFMC=$true,

        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
            [string]$FMCHost,

        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
            [string]$AuthAccessToken,

        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
            [string]$Domain
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
$AllZones        = Get-FMCZone -AuthAccessToken $AuthAccessToken -FMCHost $FMCHost -Domain $Domain -Terse
$AllNetObjects   = @()
$AllNetObjects   = Get-FMCNetworkObjects -AuthAccessToken $AuthAccessToken -FMCHost $FMCHost -Domain $Domain -Terse
$AllNetObjects  += Get-FMCNetworkGroups  -AuthAccessToken $AuthAccessToken -FMCHost $FMCHost -Domain $Domain -Terse
$AllPortObjects  = @()
$AllPortObjects  = Get-FMCPortObject -AuthAccessToken $AuthAccessToken -FMCHost $FMCHost -Domain $Domain -Terse
$AllPortObjects += Get-FMCPortGroups  -AuthAccessToken $AuthAccessToken -FMCHost $FMCHost -Domain $Domain -Terse
         }
Process {
$policyUUID = (Get-FMCAccessPolicies -Name $AccessPolicy -AuthAccessToken $AuthAccessToken -FMCHost $FMCHost -Domain $Domain -Terse).id
$uri     = "$FMCHost/api/fmc_config/v1/domain/$Domain/policy/accesspolicies/$policyUUID/accessrules"
$headers = @{ "X-auth-access-token" = "$AuthAccessToken" ;'Content-Type' = 'application/json' }
## Parsing Source or destination Security Zones

if ($SourceZones -or $DestinationZones) {
 if ($SourceZones)      {
 $SourceZones_split = $SourceZones -split ','
 $sZ = @()
 $SourceZones_split | foreach {
               $i = @()
               $i = $AllZones | Where-Object -Property name -EQ $_
               $Zone = New-Object psobject
               $Zone | Add-Member -MemberType NoteProperty -Name name -Value $i.name
               $Zone | Add-Member -MemberType NoteProperty -Name id   -Value $i.id
               $Zone | Add-Member -MemberType NoteProperty -Name type -Value $i.type
               $sZ += $Zone
               }
$sZones = New-Object psobject
$sZones | Add-Member -MemberType NoteProperty -Name objects -Value $sZ
 }
 if ($DestinationZones) {
$DestinationZones_split = $DestinationZones -split ','
$dZ = @()
$DestinationZones_split | foreach {
               $i = @()
               $i = $AllZones | Where-Object -Property name -EQ $_
               $Zone = New-Object psobject
               $Zone | Add-Member -MemberType NoteProperty -Name name -Value $i.name
               $Zone | Add-Member -MemberType NoteProperty -Name id   -Value $i.id
               $Zone | Add-Member -MemberType NoteProperty -Name type -Value $i.type
               $dZ += $Zone
               }
$dZones = New-Object psobject
$dZones | Add-Member -MemberType NoteProperty -Name objects -Value $dZ
 }
}
## /Parsing Source or destination Security Zones

## Parsing Source or destination networks
if ($SourceNetworks -or $DestinationNetworks) {
 if ($SourceNetworks) {
$literals     = @()
$objects      = @()
$SourceNetObj = @()
$SourceNetLit = @()
$SourceNetworks_split = $SourceNetworks -split ','
$SourceNetworks_split | foreach {
                     if ($_ -match '(^\d+\.\d+\.\d+\.\d+$|^\d+\.\d+\.\d+\.\d+\/\d\d$|^\d+\.\d+\.\d+\.\d+\-\d+\.\d+\.\d+\.\d+$)') {
                        $literals += $_} else {$objects += $_}}
 if ($objects) { $objects | foreach {
            $i = $AllNetObjects | Where-Object -Property name -EQ $_
            $Obj = New-Object psobject
            $Obj | Add-Member -MemberType NoteProperty -Name type -Value $i.type
            $Obj | Add-Member -MemberType NoteProperty -Name name -Value $i.name
            $Obj | Add-Member -MemberType NoteProperty -Name id   -Value $i.id
            $SourceNetObj += $Obj
            }}
 if ($literals) { $literals | foreach {
            $Obj = New-Object psobject
            $Obj | Add-Member -MemberType NoteProperty -Name value -Value "$_"
            $SourceNetLit += $Obj
                              }

                }
 $sNets = New-Object psobject 
 if ($SourceNetObj) { $sNets | Add-Member -MemberType NoteProperty -Name objects  -Value $SourceNetObj }
 if ($SourceNetLit) { $sNets | Add-Member -MemberType NoteProperty -Name literals -Value $SourceNetLit }
 }
 if ($DestinationNetworks) {
$literals     = @()
$objects      = @()
$DestinationNetObj = @()
$DestinationNetLit = @()
$DestinationNetworks_split = $DestinationNetworks -split ','
$DestinationNetworks_split | foreach {
                     if ($_ -match '(^\d+\.\d+\.\d+\.\d+$|^\d+\.\d+\.\d+\.\d+\/\d\d$|^\d+\.\d+\.\d+\.\d+\-\d+\.\d+\.\d+\.\d+$)') {
                        $literals += $_} else {$objects += $_}}
 if ($objects) { $objects | foreach {
            $i = $AllNetObjects | Where-Object -Property name -EQ $_
            $Obj = New-Object psobject
            $Obj | Add-Member -MemberType NoteProperty -Name type -Value $i.type
            $Obj | Add-Member -MemberType NoteProperty -Name name -Value $i.name
            $Obj | Add-Member -MemberType NoteProperty -Name id   -Value $i.id
            $DestinationNetObj += $Obj
            }}
 if ($literals) { $literals | foreach {
            $Obj = New-Object psobject
            $Obj | Add-Member -MemberType NoteProperty -Name value -Value "$_"
            $DestinationNetLit += $Obj
                              }

                }
 $dNets = New-Object psobject 
 if ($DestinationNetObj) { $dNets | Add-Member -MemberType NoteProperty -Name objects  -Value $DestinationNetObj }
 if ($DestinationNetLit) { $dNets | Add-Member -MemberType NoteProperty -Name literals -Value $DestinationNetLit }
 }

}
## /Parsing Source or destination networks

## Parsing Source or destination ports
if ($SourcePorts -or $DestinationPorts) {
 if ($SourcePorts) {
$literals     = @()
$objects      = @()
$SourcePortObj = @()
$SourcePortLit = @()
$SourcePorts_split = $SourcePorts -split ','
$SourcePorts_split | foreach {
                     if ($_ -match '(^\w+?\/\d+$|^\w+?\/\d+\-\d+$)') {
                        $literals += $_} else {$objects += $_}}
 if ($objects) { $objects | foreach {
            $i = $AllPortObjects | Where-Object -Property name -EQ $_
            $Obj = New-Object psobject
            $Obj | Add-Member -MemberType NoteProperty -Name type -Value $i.type
            $Obj | Add-Member -MemberType NoteProperty -Name name -Value $i.name
            $Obj | Add-Member -MemberType NoteProperty -Name id   -Value $i.id
            $SourcePortObj += $Obj
            }}
 if ($literals) { $literals | foreach {
            $i = $_ -split '\/'
            $i[0] = $i[0] -replace 'tcp','6'
            $i[0] = $i[0] -replace 'udp','17'
            $Obj = New-Object psobject
            $Obj | Add-Member -MemberType NoteProperty -Name type     -Value PortLiteral
            $Obj | Add-Member -MemberType NoteProperty -Name port     -Value $i[1]
            $Obj | Add-Member -MemberType NoteProperty -Name protocol -Value $i[0]
            $SourcePortLit += $Obj
                              }
 $sPorts = New-Object psobject 
 if ($SourcePortObj) { $sPorts | Add-Member -MemberType NoteProperty -Name objects  -Value $SourcePortObj }
 if ($SourcePortLit) { $sPorts | Add-Member -MemberType NoteProperty -Name literals -Value $SourcePortLit }
                }
 }
 if ($DestinationPorts) {
$literals     = @()
$objects      = @()
$DestinationPortObj = @()
$DestinationPortLit = @()
$DestinationPorts_split = $DestinationPorts -split ','
$DestinationPorts_split | foreach {
                     if ($_ -match '(^\w+?\/\d+$|^\w+?\/\d+\-\d+$)') {
                        $literals += $_} else {$objects += $_}}
 if ($objects) { $objects | foreach {
            $i = $AllPortObjects | Where-Object -Property name -EQ $_
            $Obj = New-Object psobject
            $Obj | Add-Member -MemberType NoteProperty -Name type -Value $i.type
            $Obj | Add-Member -MemberType NoteProperty -Name name -Value $i.name
            $Obj | Add-Member -MemberType NoteProperty -Name id   -Value $i.id
            $DestinationPortObj += $Obj
            }}
 if ($literals) { $literals | foreach {
            $i = $_ -split '\/'
            $i[0] = $i[0] -replace 'tcp','6'
            $i[0] = $i[0] -replace 'udp','17'
            $Obj = New-Object psobject
            $Obj | Add-Member -MemberType NoteProperty -Name type     -Value PortLiteral
            $Obj | Add-Member -MemberType NoteProperty -Name port     -Value $i[1]
            $Obj | Add-Member -MemberType NoteProperty -Name protocol -Value $i[0]
            $DestinationPortLit += $Obj
                              }

                }
 $dPorts = New-Object psobject 
 if ($DestinationPortObj) { $dPorts | Add-Member -MemberType NoteProperty -Name objects  -Value $DestinationPortObj }
 if ($DestinationPortLit) { $dPorts | Add-Member -MemberType NoteProperty -Name literals -Value $DestinationPortLit }
 }


}
## /Parsing Source or destination ports


if ($IntrusionPolicy) {
$ipsPolicyID = Get-FMCIntrusionPolicies -Name $IntrusionPolicy -AuthAccessToken $AuthAccessToken -FMCHost $FMCHost -Domain $Domain -Terse
$ipsPolicy = New-Object -TypeName psobject
$ipsPolicy | Add-Member -MemberType NoteProperty -name name -Value $ipsPolicyID.name
$ipsPolicy | Add-Member -MemberType NoteProperty -name id   -Value $ipsPolicyID.id
$ipsPolicy | Add-Member -MemberType NoteProperty -name type -Value $ipsPolicyID.type
}

$body = New-Object -TypeName psobject
$body | Add-Member -MemberType NoteProperty -name type            -Value 'AccessRule'
$body | Add-Member -MemberType NoteProperty -name enabled         -Value $Enabled
$body | Add-Member -MemberType NoteProperty -name name            -Value "$Name"
$body | Add-Member -MemberType NoteProperty -name action          -Value "$Action"
if ($ipsPolicy) { $body | Add-Member -MemberType NoteProperty -name ipsPolicy            -Value "$ipsPolicy" }
if ($sZones)    { $body | Add-Member -MemberType NoteProperty -name sourceZones          -Value $sZones }
if ($dZones)    { $body | Add-Member -MemberType NoteProperty -name destinationZones     -Value $dZones }
if ($sNets)     { $body | Add-Member -MemberType NoteProperty -name sourceNetworks       -Value $sNets }
if ($dNets)     { $body | Add-Member -MemberType NoteProperty -name destinationNetworks  -Value $dNets }
if ($sPorts)    { $body | Add-Member -MemberType NoteProperty -name sourcePorts          -Value $sPorts }
if ($dPorts)    { $body | Add-Member -MemberType NoteProperty -name destinationPorts     -Value $dPorts }
$body | Add-Member -MemberType NoteProperty -name logBegin        -Value $logBegin
$body | Add-Member -MemberType NoteProperty -name logEnd          -Value $logEnd
$body | Add-Member -MemberType NoteProperty -name sendEventsToFMC -Value $SendEventsToFMC
$response = Invoke-RestMethod -Method Post -Uri $uri -Headers $headers -Body ($body | ConvertTo-Json -Depth 5)
        }
End     {
#($body | ConvertTo-Json -Depth 5)
$response
#$debug
        }
}
