<# 
 Author Alif Amzari Mohd Azamee
 Azure DevOps Project URL: https://dev.azure.com/ALMAZ0773/ServiceDesk%20Password%20Reset
 Contain forked function 'New-RandomizedPassword' courtesy from William Ogle. Function has been modified to exclude certain ambiguous (difficult to read) character such as O,0,o,l,I,1. 
 Contain forked function 'Send-SDMail,Get-PDC'
 Encoding = ANSI (Windows 1252)
#>
#GlobalVariable Read from config.json#

$ScriptPath = split-path -parent $MyInvocation.MyCommand.Definition
$Config = (Get-Content -Path $ScriptPath\config.json) |ConvertFrom-Json
$LogPath = $Config.LogPath
$MailSender = $Config.MailSender
$SMTPServer = $Config.SmtpServer
$DomainName = $Config.DomainName
$ChangePasswordAtLogon = $Config.ChangePasswordAtLogon
$OrgName = $Config.OrgName
$SMSAddress = $Config.SMSAddress
$DisplayPasswordOnScreen = $Config.DisplayPasswordOnScreen
<# 
$Config = (Get-Content -Path $ScriptPath\config.txt)
$PsWho = $env:USERNAME
$PsWho = $AdmCredential.username
$LogPath = $Config[7]
$MailSender = $Config[11]
$SMTPServer = $Config[1]
$DomainName = $Config[3]
$ChangePasswordAtLogon = $Config[13]
$OrgName = $Config[15]
$SMSAddress = $Config[17]
$DisplayPasswordOnScreen = $Config[19]
#>

# $AdmCredential = Get-AdmCred
Try {
  Import-Module ActiveDirectory -ErrorAction Stop
}
Catch {
  Write-Host "Error Importing module ActiveDirectory"
  Break
}
Function Get-AdmCred {

  $AdmUsername = read-host "Enter your ADM Username (admxxxxx)"
  $AdmPassword =  read-host  "Enter your ADM password" -AsSecureString
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
  $LogHeader = "DateTime(UTC)" + $Delimiter + "PsWho" + $Delimiter + "Level" + $Delimiter + "[SAMAccountName]Data"
  $n = "`""
  $File = $LogPath
  $Who = $AdmCredential.UserName   
  $b = "["
  $c = "]"
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
      $TimeStamp + $Delimiter + $b+$Who+$c + $Delimiter + $Level + $Delimiter + $n+$Data+$n | Out-File $File -Append -ErrorAction Stop -Encoding UTF8
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
            # These are the characters !"#$%&()*+-/?@
            $null = $PasswordCharacterArray.Add(((33,34,35,36,37,38,40,41,42,43,45,47,63,64) | Get-Random | ForEach-Object {[char]$_}))
            $PasswordLength = $PasswordLength - 1
            $null = $CharacterSpaceArray.Add((33,34,35,36,37,38,40,41,42,43,45,47,63,64))
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
  $MailBodySMS = Get-Content $ScriptPath\MailBodySMS.txt -Raw
  $From = $MailSender
  # Write-Output "Sending mail" |Write-Log -Level Info 
  Switch ($SendPwdTo) {     
   Manager {
    $Subject = $MailSubject -replace('##FullName##',$FullName) -replace('##DomainName##',$DomainName)
    $Body = $MailBody -replace('##ManagerFullName##',$ManagerFullName) -replace('##FullName##',$FullName) -replace('Passwd',$Passwd)
   }
   User {
    $Subject = $MailSubject -replace('##FullName##',$FullName) -replace('##DomainName##',$DomainName)
    $Body = "Dear $FullName,<BR><BR>This is your temporary password: $Passwd<BR><BR>You cannot reply to this email.<BR><BR>Kind regards"
   }
   SMS {
    $Subject = $MailSubject -replace('##FullName##',$FullName) -replace('##DomainName##',$DomainName)
    $Body = $MailBodySMS -replace('##FullName##',$FullName) -replace('Passwd',$Passwd)
   }  
  } 
  # $SMTPServer = $SMTPServer
  try {
    Send-MailMessage -To $To -From $From -Subject $Subject -Body $Body -BodyAsHtml -SmtpServer $SMTPServer -Encoding UTF8
  }
  catch {
    $Script:SendSDMail = $false
  }
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

      $StartTime = get-date #Start stopwatch
      Write-Host "Retrieving PDC for $DomainName"
      $DC = Get-PDC -DomainName $DomainName
      Write-Host "Using $($DC.HostName) as DC for the $DomainName domain"
      Write-host "Querying $Username in Active-Directory"

      try {
          Write-Output "[$Username]Trying to reset password for $Username" |Write-Log -level Info
          Write-host "[$Username]Trying to reset password for $Username"
          $ADUser = get-aduser $UserName -server $DC -Properties Givenname,Surname,Manager,Enabled,mobilephone -ErrorAction Stop
          $Enabled = $ADUser.Enabled
          $Manager = $ADUser.Manager
          $mobilephone = $ADUser.mobilephone
          $PasswordisReset = $true
          $AccountExists = $true
      }
      catch {
          $PasswordisReset = $false
          $AccountExists = $false
      }
      Switch ($AccountExists) {
        True {
              if ($ADUser -and $Enabled -and $Manager -and $PasswordisReset){
                $PasswordisReset = $true
                $Password = New-RandomizedPassword -PasswordLength $PasswordLength -RequiresUppercase $true -RequiresNumerical $true -RequiresSpecial $true
                $SecPass = ConvertTo-SecureString $Password -AsPlainText -Force
                $Manager= Get-ADuser $manager -server $DC -Properties *| Select-Object mail,givenname,surname -ErrorAction Stop
                $ManagerEmail = $Manager.mail
                $ManagerFulLName = $Manager.givenname + " " + $Manager.Surname
                $FullName = $ADUser.GivenName + " " + $ADUser.surname
                try {
                    Write-Host "[$Username]Reseting password"
                    $PasswordisReset = $true
                    # Set-ADAccountPassword -Identity $UserName -Server $DC.HostName -NewPassword $SecPass -Credential $AdmCredential -ErrorAction Stop
                    # if ($ChangePasswordAtLogon -eq "$true") {
                    #   Set-ADUser -Identity $Username -Server $dc.HostName -ChangePasswordAtLogon $true -Credential $AdmCredential -ErrorAction Stop
                    # }
                    # else {
                    #   Set-ADUser -Identity $Username -Server $dc.HostName -ChangePasswordAtLogon $false -Credential $AdmCredential -ErrorAction Stop
                    # }
                    # Unlock-ADAccount -Identity $UserName -Credential $AdmCredential -ErrorAction Stop
                }
                catch [System.Security.Authentication.AuthenticationException],[System.UnauthorizedAccessException]{
                    $PasswordisReset = $false
                    Write-Host "Authentication Error. Check your credentianls" -ForegroundColor Red
                    Write-log -Level Error -Data "Authentication Error. Check your credentianls" 
                }
                Catch [System.Management.Automation.ParameterBindingException]{
                    $PasswordisReset = $false
                    Write-Host "Invalid Parameter -Active Directory" -ForegroundColor Red
                    Write-log -Level Error -Data "Invalid Parameter -Active Directory"
                }
                catch [Microsoft.ActiveDirectory.Management.ADServerDownException]{
                    $PasswordisReset = $false
                    Write-Host "AD service error" -ForegroundColor Red
                    Write-log -Level Error "AD service error"
                }
                catch [System.Management.Automation.PSArgumentException]{
                    $PasswordisReset = $false
                    Write-Host "Username exception" -ForegroundColor Red
                }
                catch {
                    $PasswordisReset = $false
                }
              }
              else {
                $PasswordisReset = $false
                If (!$Enabled) {
                  try {
                    $Manager = Get-ADuser $manager -server $DC | Select-Object UserPrincipalName,givenname,surname -ErrorAction Stop
                    $ManagerEmail = $Manager.UserPrincipalName
                    $ManagerFulLName = $Manager.givenname + " " + $Manager.Surname
                    write-host "[$Username]Manager is $ManagerFulLName. Email is $ManagerEmail"
                  }
                  catch {
                    Write-host "[$Username]Manager is Empty"
                  }
                  finally {
                    write-host "[$Username]Account is Disabled" -ForegroundColor Yellow
                    write-log -level Error -Data "[$Username]Account is Disabled"
                  }
                }
              }
              if ($mobilephone -and $PasswordisReset){
                  $mobilephoneisExist = $true
              }
              elseif (!$mobilephone) {
                write-host "[$Username]mobilephone is empty"
                $mobilephoneisExist = $false
              }
              if ($PasswordisReset){
                  Write-Host "[$Username]Password reset" -ForegroundColor Cyan
                  Write-log -level info -data "[$Username]Password reset"
                  if ($DisplayPasswordOnScreen -eq '$true') {
                    Write-host "[$Username]Password is: "-NoNewline 
                    Write-host "$Password" -ForegroundColor Cyan
                  }
                }
              else {
                write-host "[$Username]Error:Password not reset" -ForegroundColor Red
                Write-log -level Error -data "[$Username]Password not reset"
              } 
  
            function SendMgr {
              if ($PasswordisReset -eq $true) {
                $To =  "almaz@orsted.com"
                # $To = $ManagerEmail
                Write-Host "[$Username]Sending email password to Manager.."
                Send-SDMail -To $To -UserName $Username -FullName $Fullname -ManagerFullName $ManagerFulLName -SendPwdTo Manager -Passwd $Password
                if ($SendSDMail -eq $false) {
                  Write-Host "[$Username]Mail to Manager not sent"
                  Write-log -level Error -data "[$Username]Mail to Manager not sent"
                }
                else {
                  Write-host "[$Username]Mail sent to Manager $ManagerEmail"
                  write-log -level Info -data "[$Username]Mail sent to Manager $ManagerEmail"
                  $ManagerEmail = $null
                  }
              } #End SendMgr
  
         }
            function SendSMS {
              $To = $mobilephone.Replace(" ","")
              $To = $To + $SMSAddress
              # $To = '+60124364147'
              Write-Host "[$Username]Sending SMS to $mobilephone.."
              Send-SDMail -To $To -UserName $Username -FullName $Fullname -ManagerFullName $ManagerFulLName -SendPwdTo SMS -Passwd $Password
              write-host "[$Username]Mail sent to $To"
              Write-Log -Level Info -Data "[$Username]Mail sent to SMS $to"
            } #End SendSMS
  
          #Switch for Parameter $MailTo
              Switch -regex ($MailTo) {
                Manager { if ($PasswordisReset){
                        try {
                            $MailSentToManager = $true
                            SendMgr
                        }
                        catch {
                            $MailSentToManager = $False
                            Write-host "[$Username]Mail to Manager not sent"
                            write-log -level Error -data "[$Username]Mail to Manager not sent"
                        }
                  }
                }
                SMS { if ($PasswordisReset) {
                        try {
                          if(!$mobilephoneisExist){
                            Write-Host "[$Username]mobilephone is empty. Sending to Manager instead"
                            Write-Log -level Warning -Data "[$Username]mobilephone is empty. Sending to Manager instead"
                            SendMgr
                          }
                          Else {
                            SendSMS
                            $SMSisSent = $true
                          }
                        } 
                        catch {
                        $SMSisSent = $false
                        write-host "[$Username]SMS not Sent"
                        Write-Log -level Error -Data "[$Username]SMS not Sent"
                        }
                    }
                  }
                User { if ($PasswordisReset){
                        try {
                            $MailSentToUser = $true
                            $FullName = $ADUser.GivenName + " " + $ADUser.surname
                            $To = $ADUser.UserPrincipalName
                            # Send-SDMail -To $To -UserName $Username -FullName $Fullname -ManagerFullName $ManagerFulLName -SendPwdTo User -Passwd $Password
                            Write-host "[$Username]Mail sent to User"
                            Write-Log -Level Info -data "[$Username]Mail sent to User"
                        }
                        catch {
                            $MailSentToUser = $false
                            Write-host "[$Username]Mail not sent to user"
                            Write-Log -level Error -data "[$Username]Mail not sent to user"
                        }
                        }
                  }
              } # End Switch Parameter
        } # End AccountExist = $true
        false {
          write-host "[$Username]Account not exist" -ForegroundColor Yellow
          write-log -level Error -data "[$Username]Account not exist"
        } #End AccountExist = $false
      } #End Switch AccountExist
      $RunTime = New-TimeSpan -Start $StartTime -End (get-date)  #End Stop Watch
      "Execution time was {0} hours, {1} minutes, {2} seconds and {3} milliseconds." -f $RunTime.Hours,  $RunTime.Minutes,  $RunTime.Seconds,  $RunTime.Milliseconds 
} #end Reset-AdPwd

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
  if (!$filebrowser.FileName) {
    write-host
    write-host "No file loaded"
    write-host "Returning to main menu ..."
    start-sleep 3
    break
}
else{
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
  $DisplayPasswordOnScreen = $false
  Start-Sleep 2
  Write-Host "Input file sanitized"
  Write-Host "Total of $usercount user(s) to reset"

  Write-Host 

  

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
  Write-Host "Enter your admin account for Active Directory" -ForegroundColor Cyan
  $AdmCredential = Get-AdmCred

  While ($Menu -ne '') {
      Clear-Host
      Write-Host -ForegroundColor $TitleColor "`n`t`t $OrgName Service Desk Password Reset Menu`n"
      Write-Host -ForegroundColor $ItemTextColor "Welcome $pswho"
      Write-Host -ForegroundColor $MenuTitleColor "`nMain Menu" -NoNewline
      Write-Host -ForegroundColor $ItemTextColor -NoNewline "`n["; Write-Host -ForegroundColor $ItemNumberColor -NoNewline "1"; Write-Host -ForegroundColor $ItemTextColor -NoNewline "]"; `
      Write-Host -ForegroundColor $ItemTextColor " Reset password for a user. Password send to Manager via email."
      Write-Host -ForegroundColor $ItemTextColor -NoNewline "`n["; Write-Host -ForegroundColor $ItemNumberColor -NoNewline "2"; Write-Host -ForegroundColor $ItemTextColor -NoNewline "]"; `
      Write-Host -ForegroundColor $ItemTextColor " Reset password for a user. Password send to user via Mobile SMS."
      Write-Host -ForegroundColor $ItemTextColor -NoNewline "`n["; Write-Host -ForegroundColor $ItemNumberColor -NoNewline "3"; Write-Host -ForegroundColor $ItemTextColor -NoNewline "]"; `
      Write-Host -ForegroundColor $ItemTextColor " Reset password for multiple user. Password send to manager via email.(Format CSV with line breaks delimiter)."

      
      $menu = Read-Host "`nSelection (leave blank to quit)"
      Switch ($Menu) {
          1 {  
              Write-Host "Enter your admin account for Active Directory" -ForegroundColor Cyan
              Write-Host "Enter SamAccountName: " -NoNewline
              $Username = Read-Host
              while ($username -eq '') {
                Write-Host "Username cannot be empty." -ForegroundColor $ItemWarningColor
                Write-Host "EnterSamAccountName: " -NoNewline
                $Username = Read-host
              }
              Write-Host "Enter Password length [default is 12]: " -NoNewline
              [int]$Passwordlength = Read-Host
              if ($Passwordlength -lt 12) {
                Write-Host "Password length is $PasswordLength. Proceed with default length [12]"
                Reset-AdPwd -Username $Username
              }
              else {
                Write-Host "Password Length is $PasswordLength"
                Reset-AdPwd -Username $Username -PasswordLength $Passwordlength
              }
              # Reset-AdPwd -UserName $Username -PasswordLength $Passwordlength
              Write-Host -ForegroundColor $ItemNumberColor "`nDONE!"
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
            if ($Passwordlength -lt 12) {
              Write-Host "Password length is $PasswordLength. Proceed with default length [12]"
              Reset-AdPwd -Username $Username -MailTo SMS
            }
            else {
              Write-Host "Password Length is $PasswordLength"
              Reset-AdPwd -Username $Username -PasswordLength $Passwordlength -MailTo SMS
            }
            Write-Host -ForegroundColor $ItemNumberColor "`nDONE!"
            Write-Host "`nPress any key to return to the previous menu"
            [void][System.Console]::ReadKey($true)
            
          }
          3 {
              Write-Host "Enter Password length [default is 12]: " -NoNewline
              [int]$Passwordlength = Read-Host
              if ($Passwordlength -lt 12) {
                Write-Host "Password length is $PasswordLength. Proceed with default length [12]"
                Reset-PwdMulti
              }
              else {
                Write-Host "Password Length is $PasswordLength"
                Reset-PwdMulti -PasswordLength $Passwordlength
              }
              Write-Host -ForegroundColor $ItemNumberColor "`nDONE!"  
              Write-Host "`nPress any key to return to the previous menu"
              [void][System.Console]::ReadKey($true)           

          }
      }
  }
} #end Show-SDPasswdResetMenu

Show-SDPasswdResetMenu