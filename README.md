# Introduction

This script developed to assist password reset procedure. The goal is to automate how Service Desk handle password to customer.

  

# Features

1. The script will reset the password with the complexity meeting the criteria (12 characters, lowercase, uppercase, numbers and specials). The script also able to reset more than 12 characters if required. Ambiguous hard to read character such as **O,0,o,l,I,1.** is disregarded.

  

2. The script will have 3 main options:

![image.png](/.attachments/image-9168e93e-0072-4105-8492-df5c73450ec1.png)


3. SMS send to user's registered phone number.
![image.png](/.attachments/image-7fb55ebd-ce4f-43b0-96f2-2307aee7d0e1.png)
![image.png](/.attachments/image-ede145b6-e312-4f3b-8e1b-c2ec23dd98af.png)
4. Disabled, empty manager with empty phone number user will not be reset.
![image.png](/.attachments/image-e237dd34-d633-4f6c-b2ed-1624adbfa0ff.png)
5. Enabled user with empty phone number, their password will be send out to manager instead.
![image.png](/.attachments/image-2a79a6bb-5348-43c6-9195-0cf83276d1eb.png)

6. [ToDo] For single user password reset, the password will be displayed on PowerShell screen, with phonetics alphabetical pronunciation.

**7. If security is concern, the onscreen password output can be turn off in the config file. When multiple user option is selected, the password will not be display on screen by default.**

  

8. The script also support bulk password reset, by supplying a text file containing ***SamAccountName***, separated with 'line breaks' as delimiter.

  

9. The password will have the flag '_user must changed the password during logon_'. This flag can be set to '**$False'** in *config.json*

  

10. Allowed special characters are limited to these **!"#$%&()*+-/?@** for compatibility and readability reason.

  

11. The global variable (script scope) can be change to accommodate different environment of organization by editing the *config.json* file.

12. A separate email template file _MailBody.txt_, for immediate modification to the email sent out. 

13. Log file for tracing. 

14. AD specific error tracing when reset password.
  ![image.png](/.attachments/image-0236c615-5eb5-4f3f-b0d5-2c973012e634.png)
![image.png](/.attachments/image-507dfba6-e40b-46eb-b8b6-b55f8cac7ed0.png)


# Requirement

1. An admin account  with adequate permission to reset password.  

2. RSAT tools for ACTIVE directory PowerShell module.

# Security Limitation
The script use cmdlet **_Send-MailMessage_** to user's manager email using SMTP server **gwsmtp-07.de-prod.dk** on standard port 25 to relay message. The message is sent using plaintext. There should be a security concerned as **_Send-MailMessage_** do not support **S/MIME** or any type of encryption to protect the body of the email from **MITM** attacker for example.  The relay server, **gwsmtp-07.de-prod.dk** might not have PKI setup for an application relaying secure email, such as password. 