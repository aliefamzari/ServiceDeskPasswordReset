# Introduction 
This script is to automate password reset procedure for bulk account.

The script will reset the password with the complexity meeting the criteria (12 characters, lowercase, uppercase and numbers). Plus it is also disregard ambiguous hard to read character such as O,0,o,l,I,1.

The script will output the result on the PowerShell host screen, as well as save it as CSV file at the location of current user directory $env:USERPROFILE\result.csv

The password will have the flag 'user must changed the password during logon'. 

# Requirement

1. An adm account on domain de-prod, with adequate permission to reset password in de-prod domain.

2. RSAT tools for ACTIVE directory PowerShell module. (This can be request via OWS. Installed and enabled. For Service Desk, this module is included in SD tools)


