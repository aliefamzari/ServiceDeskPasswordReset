<# 
 Author Alif Amzari Mohd Azamee
 Azure DevOps Project URL: https://dev.azure.com/ALMAZ0773/ServiceDesk%20Password%20Reset
 Contain forked function 'New-RandomizedPassword' courtesy from William Ogle. Function has been modified to exclude certain ambiguous (difficult to read) character such as O,0,o,l,I,1. 
 Contain forked function 'Send-SDMail,Get-PDC'
 Encoding = ANSI (Windows 1252)
#>
#GlobalVariable Read from config.txt#
$ScriptPath = split-path -parent $MyInvocation.MyCommand.Definition
$Config = (Get-Content -Path $ScriptPath\config.txt)
$PsWho = $env:USERNAME
$LogPath = $Config[7]
$MailSender = $Config[11]
$SMTPServer = $Config[1]
$DomainName = $Config[3]
$ChangePasswordAtLogon = $Config[13]
$OrgName = $Config[15]
$SMSAddress = $Config[17]

Try {
  Import-Module ActiveDirectory -ErrorAction Stop
}
Catch {
  Write-Host "Error Importing module ActiveDirectory"
  Break
}
Function Get-AdmCred {

  $AdmUsername = read-host "ADM Username (admxxxxx)"
  $AdmUsername = "de-prod\"+$AdmUsername
  $AdmPassword =  read-host  "ADM password" -AsSecureString
  # $secureString = $AdmPassword | ConvertTo-SecureString -AsPlainText -Force
  $AdmCredential = New-Object System.Management.Automation.PSCredential -ArgumentList $AdmUsername, $AdmPassword
  $AdmCredential
} #end Get-AdmCred 

Function Write-Log {
  Param(
    # [Parameter(Position = 0)] [string]$File,
    # [Parameter(Position = 1)] [string]$Who,
    [Parameter(Position = 2,ValueFromPipeline = $True)] [string]$Data,
    [Parameter(Mandatory, Position = 3)] [ValidateSet("Info", "Warning", "Error")]$Level
  )
  
  $TimeStamp = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.000K") #Datetime in UTC
  $Delimiter = " "
  $LogHeader = "DateTime" + $Delimiter + "PsWho" + $Delimiter + "Level" + $Delimiter + "Data"
  $n = "`""
  $File = $LogPath
  $Who = $PsWho   
  
  Try {
    $LogFileExist = Test-Path $File
    if (!$LogFileExist) {
        $LogHeader |Out-File $File -ErrorAction Stop -Encoding UTF8 #Write log header
    } 
  }
  Catch {
    Write-Host "Error writing to log file $File - $Data" -ForegroundColor Red
  } 
  Finally {
      $TimeStamp + $Delimiter + $Who + $Delimiter + $Level + $Delimiter + $n+$Data+$n | Out-File $File -Append -ErrorAction Stop -Encoding UTF8
  } #End Catch
  
} #End Write-log

Function Get-PDC {
    [CmdletBinding()]
    Param (
      [String]$DomainName,
      [String]$DomainController,
      [Switch]$ReturnDCOnly
  
    )
    Write-Verbose "Contacting domain $DomainName"
    If ($ReturnDCOnly) {
      try {
        $DC = Get-ADDomainController -Discover -DomainName $DomainName -ErrorAction Stop
        $PDC = Get-ADDomainController -Server $DC.HostName[0] -Filter { OperationMasterRoles -like "*PDC*" } -ErrorAction Stop
      }
      catch {
        $Error[0]
        Write-Host "PDC could not be found for $DomainName" -ForegroundColor Red |Write-Log -Level Error
        Break
        $PDC = $Null
      }
    }
    Else {
      try {
        $DC = Get-ADDomainController -Discover -DomainName $DomainName -ErrorAction Stop
        $PDC = Get-ADDomainController -Server $DC.HostName[0] -Filter { OperationMasterRoles -like "*PDC*" } -ErrorAction Stop
      }
      catch {
        $Error[0]
        Write-Host "PDC could not be found for $DomainName" -ForegroundColor Red |Write-Log -Level Error
        Break
        $PDC = $Null
      }
    }  
    If ($ReturnDCOnly) {
      Return $PDC
    }
    Else {
      Return $PDC
    }
} #end Get-PDC

Function New-RandomizedPassword {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$false)]
        [ValidateRange(6, 10000)]
        [Int]$PasswordLength = 8,

        [Parameter(Mandatory = $false)]
        [bool]$RequiresUppercase = $false,

        [Parameter(Mandatory = $false)]
        [bool]$RequiresNumerical = $false,

        [Parameter(Mandatory = $false)]
        [bool]$RequiresSpecial = $false
    )

    $PasswordCharacterArray = New-Object -TypeName System.Collections.ArrayList
    $CharacterSpaceArray = New-Object -TypeName System.Collections.ArrayList

    switch ( $true )
    {
        $RequiresUppercase
        {
            # Add an uppercase character. Excluded 'I' and 'O'
            $null = $PasswordCharacterArray.Add(((65..72) + (74..78) + (80..90) | Get-Random | ForEach-Object {[char]$_}))
            $PasswordLength = $PasswordLength - 1
            $null = $CharacterSpaceArray.Add((65..72) + (74..78) + (80..90))
        }
        $RequiresNumerical
        {
            #Add a number. Excluded '0 and 1'
            $null = $PasswordCharacterArray.Add(((50..57) | Get-Random | ForEach-Object {[char]$_}))
            $PasswordLength = $PasswordLength - 1
            $null = $CharacterSpaceArray.Add((50..57))
        }
        $RequiresSpecial
        {
            # These are the characters !"$%&()*+-/?@
            $null = $PasswordCharacterArray.Add(((33,34,36,37,38,40,41,42,43,45,47,63,64) | Get-Random | ForEach-Object {[char]$_}))
            $PasswordLength = $PasswordLength - 1
            $null = $CharacterSpaceArray.Add((33,34,36,37,38,40,41,42,43,45,47,63,64))
        }
    }
    # Add a lowercase character. Excluded 'l' and 'o'
    $null = $PasswordCharacterArray.Add(((97..107) + (109,110) + (112..122) | Get-Random | ForEach-Object {[char]$_})) 
    $PasswordLength = $PasswordLength - 1
    $null = $CharacterSpaceArray.Add((97..107) + (109,110) + (112..122))

    for($i = 1; $i -le $PasswordLength; $i++)
    {
        $null = $PasswordCharacterArray.Add(($CharacterSpaceArray | Get-Random | ForEach-Object {[char]$_}))
    }

    return -join ($PasswordCharacterArray | Get-Random -Count $PasswordCharacterArray.Count)
} #end New-RandomizedPassword

Function Send-SDMail {
  [CmdletBinding()]
  param (
    [String]
    $To,
    [String]
    $UserName,
    [String]
    $FullName,
    [String]
    $ManagerFullName,
    [Parameter(Mandatory)]
    [ValidateSet("Manager","User","SMS")]
    $SendPwdTo,
    [String]
    $Passwd
  )
  $MailSubject = Get-Content $ScriptPath\MailSubject.txt -Raw
  $MailBody = Get-Content $ScriptPath\MailBody.txt -Raw
  $From = $MailSender
  # Write-Output "Sending mail" |Write-Log -Level Info 
  Switch ($SendPwdTo) {     
   Manager {
    $Subject = $MailSubject -replace('##FullName##',$FullName) -replace('##DomainName##',$DomainName)
    $Body = $MailBody -replace('##ManagerFullName##',$ManagerFullName) -replace('##FullName##',$FullName) -replace('##Password##',$Passwd)
   }
   User {
    $Subject = $MailSubject -replace('##FullName##',$FullName) -replace('##DomainName##',$DomainName)
    $Body = "Dear $FullName,<BR><BR>This is your temporary password: $Passwd<BR><BR>You cannot reply to this email.<BR><BR>Kind regards"
   }
   SMS {
    $Subject = $MailSubject -replace('##FullName##',$FullName) -replace('##DomainName##',$DomainName)
    $Body = "Dear $FullName,<BR><BR>This is your temporary password: $Passwd<BR><BR>You cannot reply to this message.<BR><BR>Kind regards"
   }  
  } 
  # $SMTPServer = $SMTPServer
  Send-MailMessage -To $To -From $From -Subject $Subject -Body $Body -BodyAsHtml -SmtpServer $SMTPServer -Encoding UTF8
} # end Send-SDMail

Function Reset-AdPwd {
  [CmdletBinding()]
  param(
      [Parameter()]
      [String]
      $UserName,
      [String]
      [Parameter()]
      [ValidateSet("Manager","SMS","ManagerSMS","User")]
      $MailTo="Manager",
      [Parameter(Mandatory=$false)]
      [Int]$PasswordLength = 12
      )

      $StartTime = get-date 
      Write-Host "Retrieving PDC for $DomainName"
      $DC = Get-PDC -DomainName $DomainName
      Write-Host "Using $($DC.HostName) as DC for the $DomainName domain"
      Write-host "Locating $Username"

      try {
          Write-Output "Trying to reset password for $Username" |Write-Log -level Info
          Write-host "Trying to reset password for $Username"
          $ADUser = get-aduser $UserName -Properties Givenname,Surname,Manager,Enabled,officephone -ErrorAction Stop
          $Enabled = $ADUser.Enabled
          $Manager = $ADUser.Manager
          $OfficePhone = $ADUser.OfficePhone
          $PasswordisReset = $true

      }
      catch {
          $PasswordisReset = $false
          write-host "$Username Account not exist"
          write-log -level Error -data "$UserName account not exist"
      }
      


      if ($ADUser -and $Enabled -and $Manager -and $PasswordisReset){
          $PasswordisReset = $true

          $Password = New-RandomizedPassword -PasswordLength $PasswordLength -RequiresUppercase $true -RequiresNumerical $true -RequiresSpecial $true
          $SecPass = ConvertTo-SecureString $Password -AsPlainText -Force
          try {
              $PasswordisReset = $true
              # Set-ADAccountPassword -Identity $Username -NewPassword $SecPass -Credential $AdmCredential -ErrorAction Stop
              # Set-ADUser -Identity $Username -ChangePasswordAtLogon $ChangePasswordAtLogon -Credential $AdmCredential
              Write-Host "Reeseting password"

          }
          catch {
              $PasswordisReset = $false
          }
      }
          else {
              $PasswordisReset = $false
              If (!$Enabled) {
                  write-host 'Account is Disabled'
                  }
                      if (!$Manager) {
                      Write-host 'Manager is Empty'
              }
          }
          if ($OfficePhone -and $PasswordisReset){
              $OfficePhoneisExist = $true
              write-host "Office phone $Officephone"
          }
          else {
              write-host "phone empty"
              $OfficePhoneisExist = $false
          }
          if ($PasswordisReset){
              Write-Host "Password for $Username reset."
              Write-log -level info -data "Password for $Username reset."
              Write-host "Password is: $Password"
          }
          else {
              write-host "Password for $Username not reset"
              Write-log -level Error -data "Password for $UserName not reset"
          }

          
      switch -regex ($MailTo) {
          Manager { if ($PasswordisReset){
              try {
                  $ManagerEmail = Get-ADuser $manager -server $DC -Properties *| Select-Object mail,givenname,surname -ErrorAction Stop
                  $ManagerEmail = $ManagerEmail.mail
                  $MailSentToManager = $true
                  $FullName = $ADUser.GivenName + " " + $ADUser.surname
                  $To = 'almaz@orsted.com' #$ManagerEmail
                  Send-SDMail -To $To -UserName $Username -FullName $Fullname -ManagerFullName $ManagerFulLName -SendPwdTo Manager -Passwd $Password
                  Write-Host 'Mail sent to manager'
                  Write-log -level info -data 'Mail sent to manager'
              }
              catch {
                  $MailSentToManager = $False
                  Write-host 'Mail to Manager not sent'
                  write-log -level Error -data 'Mail to Manager not sent'
              }

          }

          }
          SMS { if ($PasswordisReset) {
              try {
                  $SMSisSent = $true
                  $FullName = $ADUser.GivenName + " " + $ADUser.surname
                  $To = $OfficePhone.Replace(" ","")
                  $To = $To + $SMSAddress
                  Send-SDMail -To $To -UserName $Username -FullName $Fullname -ManagerFullName $ManagerFulLName -SendPwdTo SMS -Passwd $Password
                  write-host "Mail sent to SMS $to"
                  Write-Log -Level Info -data "Mail sent to SMS $to"

              }
              catch {
                  $SMSisSent = $false
                  write-host 'SMS not Sent'
                  Write-Log -level Error -Data 'SMS not Sent'
              }
          }

          }

          User { if ($PasswordisReset){
              try {
                  $MailSentToUser = $true
                  $FullName = $ADUser.GivenName + " " + $ADUser.surname
                  $To = $ADUser.UserPrincipalName
                  # Send-SDMail -To $To -UserName $Username -FullName $Fullname -ManagerFullName $ManagerFulLName -SendPwdTo User -Passwd $Password
                  Write-host 'Mail sent to User'
                  Write-Log -Level Info -data 'Mail sent to User'

              }
              catch {
                  $MailSentToUser = $false
                  Write-host "Mail not sent to user"
                  Write-Log -level Error -data 'Mail not sent to user'
              }
          }

          }
          
      } 
      $RunTime = New-TimeSpan -Start $StartTime -End (get-date) 
      "Execution time was {0} hours, {1} minutes, {2} seconds and {3} milliseconds." -f $RunTime.Hours,  $RunTime.Minutes,  $RunTime.Seconds,  $RunTime.Milliseconds 
}



function Reset-PwdMulti {
  [CmdletBinding()]
  param (
      [Parameter(Mandatory=$false)]
      [Int]$PasswordLength
      )

  Write-Host "Expecting an input file.... " -NoNewline
  Start-Sleep 2
  Add-Type -AssemblyName System.Windows.Forms
  $FileBrowser = New-Object System.Windows.Forms.OpenFileDialog -Property @{ InitialDirectory = [Environment]::GetFolderPath('Desktop') }
  $null = $FileBrowser.ShowDialog()
  Clear-host
  Write-Host "Input file loaded"
  Start-Sleep 2
  Write-Host "Sanitizing input file"
  Start-Sleep 2
  $trimpath = "$env:USERPROFILE\trim.txt"
  $File = Get-Content $FileBrowser.FileName 
  $file = $file |Out-String
  $file.Trim() |Set-Content $trimpath
  $users = (Get-Content -path $trimpath)
  $usercount = $users.Count 
  Start-Sleep 2
  Write-Host "Input file sanitized"
  Write-Host "Total of $usercount user(s) to reset"

  foreach ($item in $users){
    if ($PasswordLength -eq 0){
      Write-host "Attempting to reset for user $item"
      Reset-AdPwd -Username $item
    }
    else {
      Write-host "Attempting to reset for user $item"
      Reset-AdPwd -Username $item -PasswordLength $PasswordLength
    }
  }
} #end Reset-PwdMulti

Function Show-SDPasswdResetMenu {
  write-host 'Initializing..'
  # $pswho = $env:USERNAME
  $TitleColor = "White"
  $MenuTitleColor = "Cyan"
  $ItemNumberColor = "Cyan"
  $ItemTextColor = "White"
  $ItemWarningColor = "Yellow"
  $AdmCredential = Get-AdmCred


  While ($Menu -ne '') {
      Clear-Host
      Write-Host -ForegroundColor $TitleColor "`n`t`t $OrgName Service Desk Password Reset Menu`n"
      Write-Host -ForegroundColor $ItemTextColor "Welcome $pswho"
      Write-Host -ForegroundColor $MenuTitleColor "`nMain Menu" -NoNewline
      Write-Host -ForegroundColor $ItemTextColor -NoNewline "`n["; Write-Host -ForegroundColor $ItemNumberColor -NoNewline "1"; Write-Host -ForegroundColor $ItemTextColor -NoNewline "]"; `
      Write-Host -ForegroundColor $ItemTextColor " Reset password for a user (and send password email to Manager)"
      Write-Host -ForegroundColor $ItemTextColor -NoNewline "`n["; Write-Host -ForegroundColor $ItemNumberColor -NoNewline "2"; Write-Host -ForegroundColor $ItemTextColor -NoNewline "]"; `
      Write-Host -ForegroundColor $ItemTextColor " Reset password for a user and send to SMS"
      Write-Host -ForegroundColor $ItemTextColor -NoNewline "`n["; Write-Host -ForegroundColor $ItemNumberColor -NoNewline "3"; Write-Host -ForegroundColor $ItemTextColor -NoNewline "]"; `
      Write-Host -ForegroundColor $ItemTextColor " Reset password for multi user (CSV file needed)"
      
      $menu = Read-Host "`nSelection (leave blank to quit)"
      Switch ($Menu) {
          1 {  
              Write-Host "Enter SamAccountName: " -NoNewline
              $Username = Read-Host
              while ($username -eq '') {
                Write-Host "Username cannot be empty." -ForegroundColor $ItemWarningColor
                Write-Host "EnterSamAccountName: " -NoNewline
                $Username = Read-host
              }
              Write-Host "Enter Password length [default is 12]: " -NoNewline
              [int]$Passwordlength = Read-Host
              if ($Passwordlength -eq 0) {
                Reset-AdPwd -Username $Username
                # if ($PasswordisReset){
                #   Write-Host "Password is reset"
                # }
                # else {
                #   Write-Host "Password Not Reset"
                # }
              }
              else {
                Reset-AdPwd -Username $Username -PasswordLength $Passwordlength
                # if ($PasswordisReset){
                #   Write-Host 'Password is reset'
                # }
                # else {
                #   Write-Host "Password Not Reset"
                # }
              }
              # Reset-AdPwd -UserName $Username -PasswordLength $Passwordlength
              Write-Host -ForegroundColor $ItemNumberColor "`nScript execution complete."
              Write-Host "`nPress any key to return to the previous menu"
              [void][System.Console]::ReadKey($true)
          }
          2 {
            Write-Host "Enter SamAccountName: " -NoNewline
            $Username = Read-Host
            while ($username -eq '') {
              Write-Host "Username cannot be empty." -ForegroundColor $ItemWarningColor
              Write-Host "EnterSamAccountName: " -NoNewline
              $Username = Read-host
            }
            Write-Host "Enter Password length [default is 12]: " -NoNewline
            [int]$Passwordlength = Read-Host
            if ($Passwordlength -eq 0) {
              Reset-AdPwd -Username $Username -MailTo SMS
            }
            else {
              Reset-AdPwd -Username $Username -PasswordLength $Passwordlength -MailTo SMS
            }
            Write-Host -ForegroundColor $ItemNumberColor "`nScript execution complete."
            Write-Host "`nPress any key to return to the previous menu"
            [void][System.Console]::ReadKey($true)
            
          }
          3 {
              Write-Host "Enter Password length [default is 12]: " -NoNewline
              [int]$Passwordlength = Read-Host
              if ($Passwordlength -eq 0) {
                Reset-PwdMulti
              }
              else {
                Reset-PwdMulti -PasswordLength $Passwordlength
              }
              Write-Host -ForegroundColor $ItemNumberColor "`nScript execution complete."  
              Write-Host "`nPress any key to return to the previous menu"
              [void][System.Console]::ReadKey($true)           

          }
      }
  }
} #end Show-SDPasswdResetMenu
Show-SDPasswdResetMenu