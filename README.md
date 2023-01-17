# Introduction 
This script is to reset password for the domain de-prod.dk account.

The script will reset the password with the complexity meeting the criteria (12 characters, lowercase, uppercase and numbers). The script also able to reset more than 12 characters if needed. Plus it is also disregard ambiguous hard to read character such as O,0,o,l,I,1.

Allowed special characters are !"$%&()*+-/?@

The script will automatically send the password directly to user's manager email.
SMS send to user's registered phone number is still WIP.

The script also support bulk password reset, by supplying a text file containing SamAccountName, separated with 'line breaks' as delimiter.

The password will have the flag 'user must changed the password during logon'. 

# Requirement

1. An adm account on domain de-prod, with adequate permission to reset password in de-prod domain.

2. RSAT tools for ACTIVE directory PowerShell module. 


