
# Introduction

This script developed to assist password reset procedure. The goal is to automate how Service Desk handle password to customer.

  

# Features

1. The script will reset the password with the complexity meeting the criteria (12 characters, lowercase, uppercase, numbers and specials). The script also able to reset more than 12 characters if required. Ambiguous hard to read character such as **O,0,o,l,I,1.** is disregarded.

  

2. The script will automatically send the password directly to user's manager email.

  

3. [ToDo] SMS send to user's registered phone number.

  

4. [ToDo] For single user password reset, the password will be displayed on PowerShell screen, with phonetics alphabetical pronunciation. If there is security concern on displaying password on screen, this feature will be disabled.

  

4. The script also support bulk password reset, by supplying a text file containing ***SamAccountName***, separated with 'line breaks' as delimiter.

  

5. The password will have the flag '_user must changed the password during logon_'. This flag can be set to '**$False'** in *config.txt*

  

6. Allowed special characters are limited to these **!"$%&()*+-/?@** for compatibility and readability reason.

  

7. The global variable (script scope) can be change to accommodate different environment of organization by editing the *config.txt* file.

8. A separate email template file _MailBody.txt_, for immediate modification to the email sent out. 

9. Log file for tracing. 
  

# Requirement

1. An admin account  with adequate permission to reset password.  

2. RSAT tools for ACTIVE directory PowerShell module.

# Security Limitation
The script use cmdlet **_Send-MailMessage_** to user's manager email using SMTP server **gwsmtp-07.de-prod.dk** on standard port 25 to relay message. The message is sent using plaintext. There should be a security concerned as **_Send-MailMessage_** do not support **S/MIME** or any type of encryption to protect the body of the email from **MITM** attacker for example.  The relay server, **gwsmtp-07.de-prod.dk** might not have PKI setup for an application relaying secure email, such as password. 