# Introduction 
This script is develop is to assist password reset procedure. The goal is to automate how Service Desk handle password to customer.

Features:
1. The script will reset the password with the complexity meeting the criteria (12 characters, lowercase, uppercase and numbers). The script also able to reset more than 12 characters if needed. Plus it is also disregard ambiguous hard to read character such as O,0,o,l,I,1.
2. The script will automatically send the password directly to user's manager email.
3. [ToDo] SMS send to user's registered phone number.
4. The script also support bulk password reset, by supplying a text file containing SamAccountName, separated with 'line breaks' as delimiter.
5. The password will have the flag 'user must changed the password during logon'. 
6. Allowed special characters are !"$%&()*+-/?@
7. The global variable can be change to accomadate different environment of organization by using the config.txt file. 

# Requirement
1. An adm account on domain de-prod, with adequate permission to reset password in de-prod domain.
2. RSAT tools for ACTIVE directory PowerShell module. 


