# PowerFMC
PowerShell module for Cisco Firepower Management Center (FMC)

USE AT YOUR OWN RISK! 
This module is still under development and any feature may or may not work as intended.
Please only use in lab/development environments unless you have a strong understanding of PowerShell and the REST API
I am not responsible for any damages or downtime caused by the use of these modules.

The functions in this module invoke REST calls to the FMC API enabling the bulk creation and management of objects and policies.

To use this module, create a folder called 'PowerFMC' in one of the PowerShell module paths listed 
in the $env:PSModulePath variable (e.g. C:\Program Files\WindowsPowerShell\Modules).

Copy the contents of this repository into the PowerFMC folder.

In PowerShell, import the module with the following command:
Import-Module PowerFMC

Once imported, all the functions should be available. Begin by generating an AuthAccessToken with the New-FMCAuthAccessToken cmdlet.
It is best to output the New-AuthAccessToken into a variable to be piped into other functions.
