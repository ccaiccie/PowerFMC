function New-FMCAuthToken {
<#
 .SYNOPSIS
Obtains Domain UUID and X-auth-access-token
 .DESCRIPTION
This cmdlet will invoke a REST post against the FMC API, authenticate, and provide an X-auth-access-token and
Domain UUID for use in other functions
 .EXAMPLE
New-FMCAuthToken -fmcHost 'https://fmcrestapisandbox.cisco.com' -username 'davdecke' -password 'YDgQ7CBR'
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
            [string]$FMCHost,
        [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
            [string]$username,
        [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
            [string]$password
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
$output | Add-Member -MemberType NoteProperty -Name fmcHost         -Value $FMCHost
$output | Add-Member -MemberType NoteProperty -Name Domain          -Value $Domain
$output | Add-Member -MemberType NoteProperty -Name AuthAccessToken -Value $AuthAccessToken
$output
    }
}
function New-FMCObject {
<#
 .SYNOPSIS
Post a new object to the REST API
 .DESCRIPTION
This cmdlet will invoke a REST post against the FMC API containing custom data
 .EXAMPLE
$uri = https://fmcrestapisandbox.cisco.com/api/fmc_config/v1/domain/e276abec-e0f2-11e3-8169-6d9ed49b625f/policy/accesspolicies/005056BB-0B24-0ed3-0000-399431961128/accessrules/005056BB-0B24-0ed3-0000-000268479706
New-FMCObject -uri $uri -object ($body | ConvertTo-Json) -AuthAccessToken 637a1b3f-787b-4179-be40-e19ee2aa9e60
 .PARAMETER uri
Resource location
 .PARAMETER object
JSON data
 .PARAMETER AuthAccessToken
Session Authentication Access Token
/#>
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
This cmdlet will invoke a REST request against the FMC API and add items under /object/networks
 .EXAMPLE
$FMCHost = 'https://fmcrestapisandbox.cisco.com'
$a = New-FMCAuthToken -fmcHost $FMCHost -username 'davdecke' -password 'YDgQ7CBR'
$a | New-FMCNetworkObject -name 'PowerFMC_Net' -Network '172.21.33.0/24'                -description 'Test Object for PowerFMC'
$a | New-FMCNetworkObject -name 'PowerFMC_Host'  -Network '172.21.33.7'                 -description 'Test Object for PowerFMC'
$a | New-FMCNetworkObject -name 'PowerFMC_Range' -Network '172.21.33.100-172.21.33.200' -description 'Test Object for PowerFMC'
 .PARAMETER fmcHost
Base URL of FMC
 .PARAMETER AuthAccessToken
X-auth-accesss-token 
 .PARAMETER Domain
Domain UUID 
 .PARAMETER name
Name of the rule. Illegal characters (/,\,whitespaces) are automatically replaced with underscrores 
 .PARAMETER Network
The network, host, or range dotted-decimal IP and CIDR notation for mask
/#>
    param
    (
        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
            [string]$Name,
        [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
            [string]$Description,
        [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
            [string]$Overridable="false",
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

Invoke-RestMethod -Method Post -Uri $uri -Headers $headers -Body ($body | ConvertTo-Json)
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
$a | New-FMCNetworkGroup -Members 'PowerFMC_Host,PowerFMC_Net,PowerFMC_Range' -Name 'PowerFMC_Group' -Description 'Group made with PowerFMC'
 .PARAMETER fmcHost
Base URL of FMC
 .PARAMETER AuthAccessToken
X-auth-accesss-token 
 .PARAMETER Domain
Domain UUID 
 .PARAMETER name
Name of the rule. Illegal characters (/,\,whitespaces) are automatically replaced with underscrores 
 .PARAMETER Members
Member objects or literal networks/hosts/ranges
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
$uri = "$FMCHost/api/fmc_config/v1/domain/$Domain/object/networkgroups"
$headers = @{ "X-auth-access-token" = "$AuthAccessToken" ;'Content-Type' = 'application/json' }
$Name = $Name -replace '(\\|\/|\s)','_'

$literals = @()
$objects  = @()
$MemberArray = $Members -split ','
$MemberArray | foreach {
             if ($_ -match '(^\d+\.\d+\.\d+\.\d+$|^\d+\.\d+\.\d+\.\d+\/\d\d$|^\d+\.\d+\.\d+\.\d+\-\d+\.\d+\.\d+\.\d+$)') {
                        $literals += $_} else {$objects += $_}}
if ($objects) {
$NetworkObjects = Get-FMCNetworkObject -fmcHost $FMCHost -AuthAccessToken $AuthAccessToken -Domain $Domain -Terse
$Debug = $objects
$NetObj = @()
    $objects | foreach {
    $id = $NetworkObjects | Where-Object -Property name -EQ $_
    $id = $id.id
    $obj = New-Object psobject
    $obj | Add-Member -MemberType NoteProperty -Name id -Value $id
    $NetObj += $obj
    }
}
if ($literals) {
$NetLit = @()
    $literals | foreach {
    $obj = New-Object psobject
    $obj | Add-Member -MemberType NoteProperty -Name value -Value $_
    $NetLit += $obj
    }
}

$body = New-Object -TypeName psobject
$body | Add-Member -MemberType NoteProperty -name type        -Value "NetworkGroup"
if ($objects)  {$body | Add-Member -MemberType NoteProperty -name objects  -Value $NetObj}
if ($literals) {$body | Add-Member -MemberType NoteProperty -name literals -Value $NetLit}
$body | Add-Member -MemberType NoteProperty -name overridable -Value $Overridable
$body | Add-Member -MemberType NoteProperty -name description -Value $Description
$body | Add-Member -MemberType NoteProperty -name name        -Value $Name
Invoke-RestMethod -Method Post -Uri $uri -Headers $headers -Body ($body | ConvertTo-Json)
 }
End {
}
}
function New-FMCPortObject {
<#
 .SYNOPSIS
Create Port objects in FMC
 .DESCRIPTION
This cmdlet will invoke a REST request against the FMC API and add items under /object/protocolportobjects
 .EXAMPLE
$FMCHost = 'https://fmcrestapisandbox.cisco.com'
$a = New-FMCAuthToken -fmcHost $FMCHost -username 'davdecke' -password 'YDgQ7CBR'
$a | New-FMCPortObject -Name PowerFMC_Test123 -protocol TCP -port 123
 .PARAMETER fmcHost
Base URL of FMC
 .PARAMETER AuthAccessToken
X-auth-accesss-token 
 .PARAMETER Domain
Domain UUID 
 .PARAMETER name
Name of the rule. Illegal characters (/,\,whitespaces) are automatically replaced with underscrores 
 .PARAMETER Protocol
Protocol name; e.g. TCP, UDP
 .PARAMETER Port
Port number
/#>
    param
    (
        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
            [string]$Name,
        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
            [string]$Protocol,
        [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
            [string]$Port,
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
Create port groups in FMC
 .DESCRIPTION
This cmdlet will invoke a REST request against the FMC API and create Port Groups
 .EXAMPLE
$FMCHost = 'https://fmcrestapisandbox.cisco.com'
$a = New-FMCAuthToken -fmcHost $FMCHost -username 'davdecke' -password 'YDgQ7CBR'
$a | New-FMCPortGroup -Name PowerFMC_PortGroup -Members 'PowerFMC_Test123,PowerFMC_Test567'
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
function New-FMCAccessPolicy {
    <#
 .SYNOPSIS
Creates a new acccess policy
 .DESCRIPTION
Invokes a REST post method to create a new access policy
 .EXAMPLE
$a | New-FMCAccessPolicy -Name PowerFMC_AccessPolicy -Description 'Access Policy Created with PowerFMC'
 .PARAMETER fmcHost
Base URL of FMC
 .PARAMETER AuthAccessToken
X-auth-accesss-token 
 .PARAMETER Domain
Domain UUID 
 .PARAMETER Name
Name of access policy
 .PARAMETER ParentPolicy
Parent policy to inherit from
 .PARAMETER IntrusionPolicy
Name of default intrusion policy
/#>
    
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
$IPID = Get-FMCIntrusionPolicy -Name $IntrusionPolicy -AuthAccessToken $AuthAccessToken -FMCHost $FMCHost -Domain $Domain -Terse
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
    $Parent = Get-FMCAccessPolicy -Name $ParentPolicy -AuthAccessToken $AuthAccessToken -Domain $Domain -FMCHost $FMCHost -Terse
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
End     {}
}
function New-FMCAccessPolicyRule {
        <#
 .SYNOPSIS
Creates a new acccess policy rule
 .DESCRIPTION
Invokes a REST post method to post new rules into an access policy.
Allow for bulk rule import via pipeline. 
 .EXAMPLE
$csv = Import-Csv .\Book1.csv
$csv[1]

AccessPolicy        : TST1111
Name                : BulkTest2
Action              : BLOCK_RESET
SourceZones         : MC-INSIDE
DestinationZones    : MC-OUTSIDE
SourceNetworks      : 100.1.1.2
DestinationNetworks : 200.1.1.2
SourcePorts         :
DestinationPorts    : tcp/112,udp/1002

$csv | New-FMCAccessPolicyRule -AuthAccessToken $a.AuthAccessToken -Domain $a.Domain -FMCHost $a.fmcHost
 .PARAMETER fmcHost
Base URL of FMC
 .PARAMETER AuthAccessToken
X-auth-accesss-token 
 .PARAMETER Domain
Domain UUID 
 .PARAMETER Name
Rule Name
 .PARAMETER AccessPolicy
Access policy rule will belong to
 .PARAMETER Action
Action rule will take (e.g. Allow or Block)
 .PARAMETER SourceZones
Source zone. Multiple items must be separated by commas
 .PARAMETER DestinationZones
Destination zone. Multiple items must be separated by commas
 .PARAMETER SourceNetworks
Source network. Multiple items must be separated by commas
Will accept either a network object/group, or a literal host/network/range value: e.g. 10.10.10.0/24
 .PARAMETER DestinationNetworks
Destination network. Multiple items must be separated by commas
Will accept either a network object/group, or a literal host/network/range value: e.g. 10.10.10.0/24
 .PARAMETER SourcePorts
Source port(s). Multiple items must be separated by commas
Will accept either a port object/group, or a literal port value: e.g. tcp/890
 .PARAMETER DestinationPorts
Destination port(s). Multiple items must be separated by commas.
Will accept either a port object/group, or a literal port value: e.g. tcp/890
 .PARAMETER Enabled
Sets enable parameter to true or false (true by default)
 .PARAMETER IntrusionPolicy
Selects the IPS policy for the rule
/#>

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
            [bool]$LogEnd=$false,

        [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
            [bool]$SendEventsToFMC=$false,

        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
            [string]$FMCHost,

        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
            [string]$AuthAccessToken,

        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
            [string]$Domain
    )
Begin   {
$BeginTime = Get-Date
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
$AllNetObjects   = Get-FMCNetworkObject -AuthAccessToken $AuthAccessToken -FMCHost $FMCHost -Domain $Domain -Terse
$AllNetObjects  += Get-FMCNetworkGroup  -AuthAccessToken $AuthAccessToken -FMCHost $FMCHost -Domain $Domain -Terse
$AllPortObjects  = @()
$AllPortObjects  = Get-FMCPortObject -AuthAccessToken $AuthAccessToken -FMCHost $FMCHost -Domain $Domain -Terse
$AllPortObjects += Get-FMCPortGroup  -AuthAccessToken $AuthAccessToken -FMCHost $FMCHost -Domain $Domain -Terse
         }
Process {
$policyUUID = (Get-FMCAccessPolicy -Name $AccessPolicy -AuthAccessToken $AuthAccessToken -FMCHost $FMCHost -Domain $Domain -Terse).id
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
$ipsPolicyID = Get-FMCIntrusionPolicy -Name $IntrusionPolicy -AuthAccessToken $AuthAccessToken -FMCHost $FMCHost -Domain $Domain -Terse
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
if ($ipsPolicy) { $body | Add-Member -MemberType NoteProperty -name ipsPolicy            -Value $ipsPolicy }
if ($sZones)    { $body | Add-Member -MemberType NoteProperty -name sourceZones          -Value $sZones }
if ($dZones)    { $body | Add-Member -MemberType NoteProperty -name destinationZones     -Value $dZones }
if ($sNets)     { $body | Add-Member -MemberType NoteProperty -name sourceNetworks       -Value $sNets }
if ($dNets)     { $body | Add-Member -MemberType NoteProperty -name destinationNetworks  -Value $dNets }
if ($sPorts)    { $body | Add-Member -MemberType NoteProperty -name sourcePorts          -Value $sPorts }
if ($dPorts)    { $body | Add-Member -MemberType NoteProperty -name destinationPorts     -Value $dPorts }
$body | Add-Member -MemberType NoteProperty -name logBegin        -Value $logBegin
$body | Add-Member -MemberType NoteProperty -name logEnd          -Value $logEnd
$body | Add-Member -MemberType NoteProperty -name sendEventsToFMC -Value $SendEventsToFMC
Invoke-RestMethod -Method Post -Uri $uri -Headers $headers -Body ($body | ConvertTo-Json -Depth 5)
        }
End     {
$EndTime = Get-Date
(New-TimeSpan -Start $BeginTime -End $EndTime).TotalMinutes
#($body | ConvertTo-Json -Depth 5)
#$response
#$debug
        }
}
function Get-FMCObject {
    <#
 .SYNOPSIS
Post a new object to the REST API
 .DESCRIPTION
This cmdlet will invoke a REST get against the FMC API path
 .EXAMPLE
$uri = https://fmcrestapisandbox.cisco.com/api/fmc_config/v1/domain/e276abec-e0f2-11e3-8169-6d9ed49b625f/policy/accesspolicies/005056BB-0B24-0ed3-0000-399431961128/accessrules/005056BB-0B24-0ed3-0000-000268479706
Get-FMCObject -uri $uri -AuthAccessToken 637a1b3f-787b-4179-be40-e19ee2aa9e60
 .PARAMETER uri
Resource location
 .PARAMETER AuthAccessToken
Session Authentication Access Token
/#>
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
function Get-FMCNetworkObject {
<#
 .SYNOPSIS
Displays network objects in FMC
 .DESCRIPTION
This cmdlet will invoke a REST request against the FMC API and retrieve items under /object/networks
 .EXAMPLE
Get-FMCNetworkObject -fmcHost "https://fmcrestapisandbox.cisco.com" -username 'davdecke' -password 'YDgQ7CBR'
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
function Get-FMCNetworkGroup {
<#
 .SYNOPSIS
Displays network groups in FMC
 .DESCRIPTION
This cmdlet will invoke a REST request against the FMC API and retrieve items under /object/networkgroups
 .EXAMPLE
# Get-FMCNetworkObject -fmcHost "https://fmcrestapisandbox.cisco.com" -AuthAccessToken 'e276abec-e0f2-11e3-8169-6d9ed49b625f' -Domain '618846ea-6e3e-4d69-8f30-55f31b52ca3e'
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
    <#
 .SYNOPSIS
Displays port objects in FMC
 .DESCRIPTION
This cmdlet will invoke a REST request against the FMC API and retrieve port objects
 .EXAMPLE
Get-FMCPortObject -fmcHost "https://fmcrestapisandbox.cisco.com" -username 'davdecke' -password 'YDgQ7CBR' -Name PowerFMC*
 .PARAMETER fmcHost
Base URL of FMC
 .PARAMETER AuthAccessToken
X-auth-accesss-token 
 .PARAMETER Domain
Domain UUID 
 .PARAMETER Name
Name of port object(s). Wildcards accepted
/#>
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
function Get-FMCPortGroup {
    <#
 .SYNOPSIS
Displays port group objects in FMC
 .DESCRIPTION
This cmdlet will invoke a REST request against the FMC API and retrieve port group objects
 .EXAMPLE
Get-FMCPortObject -fmcHost "https://fmcrestapisandbox.cisco.com" -username 'davdecke' -password 'YDgQ7CBR' -Name PowerFMC*
 .PARAMETER fmcHost
Base URL of FMC
 .PARAMETER AuthAccessToken
X-auth-accesss-token 
 .PARAMETER Domain
Domain UUID 
 .PARAMETER Name
Name of port group object(s). Wildcards accepted
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
function Get-FMCAccessPolicy {
    <#
 .SYNOPSIS
Displays access policies in FMC
 .DESCRIPTION
This cmdlet will invoke a REST request against the FMC API and retrieve access policies
 .EXAMPLE
 $a | Get-FMCAccessPolicy -Name PowerFMC_Policy
  .PARAMETER fmcHost
Base URL of FMC
 .PARAMETER AuthAccessToken
X-auth-accesss-token 
 .PARAMETER Domain
Domain UUID 
 .PARAMETER Name
Name of access policy. Wildcards accepted
/#>
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
function Get-FMCIntrusionPolicy {
    <#
 .SYNOPSIS
Displays intrusion policies in FMC
 .DESCRIPTION
This cmdlet will invoke a REST request against the FMC API and retrieve intrusion policies
 .EXAMPLE
 Get-FMCIntrusionPolicy -AuthAccessToken 77df501f-d85a-44c6-9ec4-29007a29dbd7 -Domain e276abec-e0f2-11e3-8169-6d9ed49b625f -FMCHost https://fmcrestapisandbox.cisco.com
  .PARAMETER fmcHost
Base URL of FMC
 .PARAMETER AuthAccessToken
X-auth-accesss-token 
 .PARAMETER Domain
Domain UUID 
 .PARAMETER Name
Name of intrusion policy. Wildcards accepted
/#>
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
function Get-FMCFilePolicy {
    <#
 .SYNOPSIS
Displays file policies in FMC
 .DESCRIPTION
This cmdlet will invoke a REST request against the FMC API and retrieve file policies
 .EXAMPLE
 Get-FMCFilePolicy -AuthAccessToken 77df501f-d85a-44c6-9ec4-29007a29dbd7 -Domain e276abec-e0f2-11e3-8169-6d9ed49b625f -FMCHost https://fmcrestapisandbox.cisco.com
  .PARAMETER fmcHost
Base URL of FMC
 .PARAMETER AuthAccessToken
X-auth-accesss-token 
 .PARAMETER Domain
Domain UUID 
 .PARAMETER Name
Name of file policy. Wildcards accepted
/#>
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
$uri     = "$FMCHost/api/fmc_config/v1/domain/$Domain/policy/filepolicies?offset=0&limit=25&expanded=$Expanded"
$response = Invoke-RestMethod -Method Get -Uri $uri -Headers $headers
$pages = $response.paging.pages
$items = $response.items
$offset = 0
while ($pages -gt 1) {
    $offset   = $offset+25
    $pages--
    $uri      = "$FMCHost/api/fmc_config/v1/domain/$Domain/policy/filepolicies?offset=$offset&limit=25&expanded=$Expanded"
    $response = Invoke-RestMethod -Method Get -Uri $uri -Headers $headers
    $items   += $response.items
                     }
$response = $items | Where-Object -Property name -Like "$Name"
        }
End     {
$response
        }
}
function Get-FMCAccessPolicyRule {
    <#
 .SYNOPSIS
Displays rules in an access policy
 .DESCRIPTION
This cmdlet will invoke a REST request against the FMC API and retrieve access policy rules
 .EXAMPLE
$a | Get-FMCAccessPolicyRule -AccessPolicy PowerFMC_AccessPolicy
  .PARAMETER fmcHost
Base URL of FMC
 .PARAMETER AuthAccessToken
X-auth-accesss-token 
 .PARAMETER Domain
Domain UUID 
 .PARAMETER AccessPolicy
Name of the access policy to query
 .PARAMETER RuleName
Name of the rule(s). Wildcards accepted
/#>
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
$ContainerUUID = Get-FMCAccessPolicy -Name $AccessPolicy -AuthAccessToken $AuthAccessToken -FMCHost $FMCHost -Domain $Domain -Terse
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
        <#
 .SYNOPSIS
Displays zones defined in FMC
 .DESCRIPTION
This cmdlet will invoke a REST request against the FMC API and display zones
 .EXAMPLE
Get-FMCZone -Name *INSIDE* -AuthAccessToken 77df501f-d85a-44c6-9ec4-29007a29dbd7 -Domain e276abec-e0f2-11e3-8169-6d9ed49b625f -FMCHost https://fmcrestapisandbox.cisco.com
  .PARAMETER fmcHost
Base URL of FMC
 .PARAMETER AuthAccessToken
X-auth-accesss-token 
 .PARAMETER Domain
Domain UUID 
 .PARAMETER Name
Name of the zone(s). Wildcards accepted
/#>
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
        <#
 .SYNOPSIS
Removes an object via the REST API
 .DESCRIPTION
This cmdlet will invoke a REST delete method against a URI
 .EXAMPLE
$uri = https://fmcrestapisandbox.cisco.com/api/fmc_config/v1/domain/e276abec-e0f2-11e3-8169-6d9ed49b625f/policy/accesspolicies/005056BB-0B24-0ed3-0000-399431961128/accessrules/005056BB-0B24-0ed3-0000-000268479706
Remove-FMCObject -uri $uri -AuthAccessToken 637a1b3f-787b-4179-be40-e19ee2aa9e60
 .PARAMETER uri
Resource location
 .PARAMETER AuthAccessToken
Session Authentication Access Token
/#>
param
    (
        [Parameter(Mandatory=$false, ValueFromPipeline=$true)]
            [string]$uri,
        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
            [string]$AuthAccessToken,
        [Parameter(Mandatory=$false, ValueFromPipeline=$true)]
            $Object
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
if ($Object) { $uri = $Object.links.self }
$headers = @{ "X-auth-access-token" = "$AuthAccessToken" }
$response = Invoke-RestMethod -Method Delete -Uri $uri -Headers $headers
$response
        }
End {$uri}
}
function Update-FMCAccessPolicyRule {
        <#
 .SYNOPSIS
Creates a new acccess policy rule
 .DESCRIPTION
Invokes a REST post method to post new rules into an access policy.
Allow for bulk rule import via pipeline. 
 .EXAMPLE

 .PARAMETER fmcHost
Base URL of FMC
 .PARAMETER AuthAccessToken
X-auth-accesss-token 
 .PARAMETER Domain
Domain UUID 
 .PARAMETER Name
Rule Name
 .PARAMETER AccessPolicy
Access policy rule will belong to
 .PARAMETER Action
Action rule will take (e.g. Allow or Block)
 .PARAMETER SourceZones
Source zone. Multiple items must be separated by commas
 .PARAMETER DestinationZones
Destination zone. Multiple items must be separated by commas
 .PARAMETER SourceNetworks
Source network. Multiple items must be separated by commas
Will accept either a network object/group, or a literal host/network/range value: e.g. 10.10.10.0/24
 .PARAMETER DestinationNetworks
Destination network. Multiple items must be separated by commas
Will accept either a network object/group, or a literal host/network/range value: e.g. 10.10.10.0/24
 .PARAMETER SourcePorts
Source port(s). Multiple items must be separated by commas
Will accept either a port object/group, or a literal port value: e.g. tcp/890
 .PARAMETER DestinationPorts
Destination port(s). Multiple items must be separated by commas.
Will accept either a port object/group, or a literal port value: e.g. tcp/890
 .PARAMETER Enabled
Sets enable parameter to true or false (true by default)
 .PARAMETER IntrusionPolicy
Selects the IPS policy for the rule
/#>

    param
    (
        [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$false)]
        [ValidateSet("True","False")] 
            [string]$Enabled,

        [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$false)]
        [ValidateSet("ALLOW","TRUST","MONITOR","BLOCK","BLOCK_RESET","BLOCK_INTERACTIVE","BLOCK_RESET_INTERACTIVE")] 
            [string]$Action,

        [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$false)]
            [string]$SourceZones,

        [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$false)]
            [string]$DestinationZones,

        [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$false)]
            [string]$SourceNetworks,

        [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$false)]
            [string]$DestinationNetworks,

        [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$false)]
            [string]$SourcePorts,

        [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$false)]
            [string]$DestinationPorts,

        [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$false)]
            [string]$IntrusionPolicy,

        [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$false)]
            [string]$FilePolicy,

        [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$false)]
            [bool]$LogBegin,

        [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$false)]
            [bool]$LogEnd,

        [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$false)]
            [bool]$SendEventsToFMC,

        [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$false)]
            [string]$Comments,

        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
            [string]$FMCHost,

        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
            [string]$AuthAccessToken,

        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
            [string]$Domain,

        [Parameter(Mandatory=$true, ValueFromPipeline=$true)]
            $InputObject
    )
Begin   {
$BeginTime = Get-Date
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
if ($SourceZones -or $DestinationZones) {$AllZones = Get-FMCZone -AuthAccessToken $AuthAccessToken -FMCHost $FMCHost -Domain $Domain -Terse}
if ($IntrusionPolicy)                   {$AllIPSPolicies  = Get-FMCIntrusionPolicy -AuthAccessToken $AuthAccessToken -FMCHost $FMCHost -Domain $Domain -Terse}
if ($FilePolicy)                        {$AllFilePolicies = Get-FMCIntrusionPolicy -AuthAccessToken $AuthAccessToken -FMCHost $FMCHost -Domain $Domain -Terse}
if ($SourceNetworks -or $DestinationNetworks) {
       $AllNetObjects   = @()
       $AllNetObjects   = Get-FMCNetworkObject -AuthAccessToken $AuthAccessToken -FMCHost $FMCHost -Domain $Domain -Terse
       $AllNetObjects  += Get-FMCNetworkGroup  -AuthAccessToken $AuthAccessToken -FMCHost $FMCHost -Domain $Domain -Terse
       }
if ($SourcePorts -or $DestinationPorts) {
       $AllPortObjects  = @()
       $AllPortObjects  = Get-FMCPortObject -AuthAccessToken $AuthAccessToken -FMCHost $FMCHost -Domain $Domain -Terse
       $AllPortObjects += Get-FMCPortGroup  -AuthAccessToken $AuthAccessToken -FMCHost $FMCHost -Domain $Domain -Terse
       }
         }
Process {
$ruleUUID   = $InputObject.id
$policyUUID = $InputObject.metadata.accessPolicy.id
$uri     = "$FMCHost/api/fmc_config/v1/domain/$Domain/policy/accesspolicies/$policyUUID/accessrules/$ruleUUID"
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

if (!$Enabled) {$Enabled = $InputObject.enabled}
if (!$Action)  {$Action = $InputObject.action}
if ($IntrusionPolicy) {
$ipsPolicyID = Get-FMCIntrusionPolicy -Name $IntrusionPolicy -AuthAccessToken $AuthAccessToken -FMCHost $FMCHost -Domain $Domain -Terse
$ipsPolicy = New-Object -TypeName psobject
$ipsPolicy | Add-Member -MemberType NoteProperty -name name -Value $ipsPolicyID.name
$ipsPolicy | Add-Member -MemberType NoteProperty -name id   -Value $ipsPolicyID.id
$ipsPolicy | Add-Member -MemberType NoteProperty -name type -Value $ipsPolicyID.type
}

if ($FilePolicy) {
$fPolicyID = Get-FMCFilePolicy -Name $FilePolicy -AuthAccessToken $AuthAccessToken -FMCHost $FMCHost -Domain $Domain -Terse
$fPolicy = New-Object -TypeName psobject
$fPolicy | Add-Member -MemberType NoteProperty -name name -Value $fPolicyID.name
$fPolicy | Add-Member -MemberType NoteProperty -name id   -Value $fPolicyID.id
$fPolicy | Add-Member -MemberType NoteProperty -name type -Value $fPolicyID.type
}

if ($Comments) {
 $newComments = New-Object -TypeName psobject
 $newComments | Add-Member -MemberType NoteProperty -Name comment1 -Value $Comments
 }

$body = New-Object -TypeName psobject
$body | Add-Member -MemberType NoteProperty -name enabled         -Value $Enabled
$body | Add-Member -MemberType NoteProperty -name name            -Value $InputObject.Name
$body | Add-Member -MemberType NoteProperty -name id              -Value $ruleUUID
$body | Add-Member -MemberType NoteProperty -name action          -Value $Action
if ($ipsPolicy)       { $body | Add-Member -MemberType NoteProperty -name ipsPolicy            -Value $ipsPolicy }
if ($fPolicy)         { $body | Add-Member -MemberType NoteProperty -name filePolicy           -Value $fPolicy }
if ($sZones)          { $body | Add-Member -MemberType NoteProperty -name sourceZones          -Value $sZones }
if ($dZones)          { $body | Add-Member -MemberType NoteProperty -name destinationZones     -Value $dZones }
if ($sNets)           { $body | Add-Member -MemberType NoteProperty -name sourceNetworks       -Value $sNets }
if ($dNets)           { $body | Add-Member -MemberType NoteProperty -name destinationNetworks  -Value $dNets }
if ($sPorts)          { $body | Add-Member -MemberType NoteProperty -name sourcePorts          -Value $sPorts }
if ($dPorts)          { $body | Add-Member -MemberType NoteProperty -name destinationPorts     -Value $dPorts }
if ($Comments)        { $body | Add-Member -MemberType NoteProperty -name newComments          -Value $newComments }
if ($logBegin)        { $body | Add-Member -MemberType NoteProperty -name logBegin             -Value $logBegin }
if ($LogEnd)          { $body | Add-Member -MemberType NoteProperty -name logEnd               -Value $logEnd }
if ($SendEventsToFMC) { $body | Add-Member -MemberType NoteProperty -name sendEventsToFMC      -Value $SendEventsToFMC }
Invoke-RestMethod -Method Put -Uri $uri -Headers $headers -Body ($body | ConvertTo-Json -Depth 5)
        }
End     {
$EndTime = Get-Date
#$uri
#($body | ConvertTo-Json -Depth 5)
#(New-TimeSpan -Start $BeginTime -End $EndTime).TotalMinutes
#($body | ConvertTo-Json -Depth 5)
#$response
#$debug
        }
}
