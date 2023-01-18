
# Introduction

This script developed to assist password reset procedure. The goal is to automate how Service Desk handle password to customer.

  

# Features

1. The script will reset the password with the complexity meeting the criteria (12 characters, lowercase, uppercase, numbers and specials). The script also able to reset more than 12 characters if needed. Ambiguous hard to read character such as O,0,o,l,I,1. is disregarded.

  

2. The script will automatically send the password directly to user's manager email.

  

3. [ToDo] SMS send to user's registered phone number.

  

4. [ToDo] For single user password reset, the password will be displayed on PowerShell screen, with phonetics alphabetical pronunciation.

  

4. The script also support bulk password reset, by supplying a text file containing ***SamAccountName***, separated with 'line breaks' as delimiter.

  

5. The password will have the flag 'user must changed the password during logon'. This flag can be set to '**$False'** in *config.txt*

  

6. Allowed special characters are limited to these **!"$%&()*+-/?@** for compatibility and readbility reason.

  

7. The global variable can be change to accommodate different environment of organization by editing the *config.txt* file.

  

# Requirement

1. An admin account  with adequate permission to reset password.  

2. RSAT tools for ACTIVE directory PowerShell module.