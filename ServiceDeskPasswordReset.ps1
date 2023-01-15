<# 
 Author Alif Amzari Mohd Azamee
 Azure DevOps Project URL: https://dev.azure.com/ALMAZ0773/ServiceDesk%20Password%20Reset
 Contain forked function 'New-RandomizedPassword' courtesy from William Ogle. Function has been modified to exclude certain ambiguous (difficult to read) character such as O,0,o,l,I,1. 
 Contain forked function 'Send-SDMail 
 Contain external function Get-PDC
#>
Import-Module ActiveDirectory
$PsWho = $env:USERNAME
$logpath = 'c:\app\write-log.log'
$scriptpath = split-path -parent $MyInvocation.MyCommand.Definition

Function Write-Log {
  Param(
    [Parameter(Position = 0)] [string]$File,
    [Parameter(Position = 1)] [string]$Who,
    [Parameter(Position = 2)] [string]$Data,
    [Parameter(Mandatory, Position = 3)] [ValidateSet("Info", "Warning", "Error")]$Level
  )
  
  $TimeStamp = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.000K") #Datetime in UTC
  $Delimiter = " "
  $LogHeader = "DateTime" + $Delimiter + "PsWho" + $Delimiter + "Level" + $Delimiter + "Data"
  $n = "`""
    
  
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
        Write-Host "PDC could not be found for $DomainName" -ForegroundColor Red
        Write-Log -File $logpath -Who $PsWho -Level Error -Data "PDC could not be found for $DomainName"
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
        Write-Host "PDC could not be found for $DomainName" -ForegroundColor Red
        Write-Log -File $logpath -Who $PsWho -Level Error -Data "PDC could not be found for $DomainName"
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
            $null = $PasswordCharacterArray.Add(((33..38) + (40..47) + (58..64) | Get-Random | ForEach-Object {[char]$_}))
            $PasswordLength = $PasswordLength - 1
            $null = $CharacterSpaceArray.Add((33..38) + (40..47) + (58..64))
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
    [ValidateSet("Manager","User")]
    $SendPwdTo,
    [String]
    $Passwd,
    [String]
    $LogFile
  )
  $MailTempPasswordSubject = Get-Content $scriptpath\subject.txt
  $MailTempPasswordText = "Hi ##ManagerFullname##, <BR><BR>This is the temporary password for the account belonging to ##Username##:<BR><BR>##Password##<BR><BR>Please make sure to hand-over the password to the user.<BR><BR>You cannot reply to this email.<BR><BR>Kind regards,<BR>Ørsted SD AAC" 
  # $MailTempPasswordText = Get-Content $scriptpath\body.txt

  [Array]$MailAttachments = $null
  Write-Host "Sending mail"
  $From = "Ørsted SD AAC <SD_Assistance@orsted.com>"
  Switch ($SendPwdTo) {     
   Manager {
    # Write-Log $LogFile "Sending mail with password to $To"
    $Subject = $MailTempPasswordSubject -replace('##FullName##',$FullName)
    $Body = $MailTempPasswordText -replace('##ManagerFullName##',$ManagerFullName) -replace('##UserName##',$UserName) -replace('##Password##',$Passwd)
   }
   User {
    # Write-Log $LogFile "Sending mail with the temporary password to $To"
    $Subject = "Password for de-prod.dk"
    $Body = "Dear $FullName,<BR><BR>This is your temporary password: $Passwd<BR><BR>You cannot reply to this email.<BR><BR>Kind regards"
   }  
  } 
  $SMTPServer = "gwsmtp-07.de-prod.dk"
  If ($null -eq $MailAttachments) {
    Send-MailMessage -To $To -From $From -Subject $Subject -Body $Body -BodyAsHtml -Encoding UTF8 -SmtpServer $SMTPServer
    } 
    Else {
      Send-MailMessage -To $To -From $From -Subject $Subject -Body $Body -BodyAsHtml -Encoding UTF8 -SmtpServer $SMTPServer -Attachments $MailAttachments -Verbose
    }  
} # end Send-SDMail

Function Reset-DeprodPwd {
  [CmdletBinding()]
  param (
      [Parameter()]
      [string]
      $Username
      )
      $StartTime = get-date 
      Write-Host "Retrieving PDC for de-prod.dk"
      $DC = Get-PDC -DomainName de-prod.dk
      Write-Host "Using $($DC.HostName) as DC for the de-prod.dk domain"
      Write-host "Locating $Username"
      $AccountExists = $False
      try {
          $IfUserExist = Get-ADUser $Username -Properties Givenname,Surname,Manager -Server $DC -ErrorAction Stop
          if ($IfUserExist) {
              $AccountExists = $true
              $PasswordReset = $true
              $Password = New-RandomizedPassword -PasswordLength 12 -RequiresUppercase $true -RequiresNumerical $true -RequiresSpecial $true
              $SecPass = ConvertTo-SecureString $Password -AsPlainText -Force
              $Mgr = $IfUserExist.manager |Get-ADuser -server $DC -Properties *| Select-Object mail,givenname,surname
              $ManagerEmail = $Mgr.mail
              $ManagerFulLName = $Mgr.Givenname + " " + $Mgr.Surname
              try {
                  $PasswordReset = $true
                  Write-Verbose "Trying to reset password for $Username"
                  Write-Log -File $logpath -who $PsWho -Level Info -Data "Trying to reset password for $Username"
                  # Set-ADAccountPassword -Identity $Username -NewPassword $SecPass -ErrorAction Stop
                  # Set-ADUser -Identity $Username -ChangePasswordAtLogon $true
                  $Fullname = $IfUserExist.Givenname + " " + $IfUserExist.surname
                  $To = 'almaz@orsted.com' #$ManagerEmail
                  Send-SDMail -To $To -UserName $Username -FullName $Fullname -ManagerFullName $ManagerFulLName -SendPwdTo Manager -Passwd $Password 
                
              }
              catch {
                  $PasswordReset = $False                 
              }
              Finally {
                  if ($PasswordReset -eq $true) {
                      Write-Verbose "Password for $Username reset"
                      Write-Log -File $logpath -who $PsWho -Level Info -Data "Password for $Username reset"
                  }
                  else {
                      Write-Verbose "Error:Password for $Username failed to reset"
                      Write-Log -File $logpath -who $PsWho -Level Error -Data "Error:Password for $Username failed to reset"
                  } #end else
              } #end finally
            } #end if              
          } #end try
          catch {
            Write-host "Account $username notexist"
            Write-Log -File $logpath -who $PsWho -Level Warning -Data "Account $username notexist"
          }
          $RunTime = New-TimeSpan -Start $StartTime -End (get-date) 
"Execution time was {0} hours, {1} minutes, {2} seconds and {3} milliseconds." -f $RunTime.Hours,  $RunTime.Minutes,  $RunTime.Seconds,  $RunTime.Milliseconds  
} #end Reset-DeprodPwd

Function Show-SDPasswdResetMenu {
  write-host 'Initializing..'
  $pswho = $env:USERNAME
  $TitleColor = "White"
  $MenuTitleColor = "Cyan"
  $ItemNumberColor = "Cyan"
  $ItemTextColor = "White"


  While ($Menu -ne '') {
      Clear-Host
      Write-Host -ForegroundColor $TitleColor "`n`t`t Service Desk Password Reset Menu`n"
      Write-Host -ForegroundColor $ItemTextColor "Welcome $pswho"
      Write-Host -ForegroundColor $MenuTitleColor "`nMain Menu" -NoNewline
      Write-Host -ForegroundColor $ItemTextColor -NoNewline "`n["; Write-Host -ForegroundColor $ItemNumberColor -NoNewline "1"; Write-Host -ForegroundColor $ItemTextColor -NoNewline "]"; `
      Write-Host -ForegroundColor $ItemTextColor " Reset password for a user (and send password email to Manager)"
      Write-Host -ForegroundColor $ItemTextColor -NoNewline "`n["; Write-Host -ForegroundColor $ItemNumberColor -NoNewline "2"; Write-Host -ForegroundColor $ItemTextColor -NoNewline "]"; `
      Write-Host -ForegroundColor $ItemTextColor " Reset password for multi user (CSV file needed)"
      $menu = Read-Host "`nSelection (leave blank to quit)"
      Switch ($Menu) {
          1 {  
              Write-Host "Enter SamAccountName: " -NoNewline
              $Username = Read-Host
              Reset-DeProdPwd -UserName $Username
              Write-Host -ForegroundColor $ItemNumberColor "`nScript execution complete."
              Write-Host "`nPress any key to return to the previous menu"
              [void][System.Console]::ReadKey($true)
          }
          2 {
              Write-Host "Expecting an input file.... " -NoNewline
              Start-Sleep 2
              Add-Type -AssemblyName System.Windows.Forms
              $FileBrowser = New-Object System.Windows.Forms.OpenFileDialog -Property @{ InitialDirectory = [Environment]::GetFolderPath('Desktop') }
              $null = $FileBrowser.ShowDialog()
              Clear-host
              $trimpath = "$env:USERPROFILE\trim.txt"
              $file = Get-Content $FileBrowser.FileName 
              $file = $file |Out-String
              $file.Trim() |Set-Content $trimpath
              $users = Get-Content $trimpath 
              Write-Output $users
              Write-Host -ForegroundColor $ItemNumberColor "`nScript execution complete."  
              Write-Host "`nPress any key to return to the previous menu"
              [void][System.Console]::ReadKey($true)           

          }
      }
  }
} #end Show-SDPasswdResetMenu

# write-host "Expecting input file..."
# Start-sleep 2
# Add-Type -AssemblyName System.Windows.Forms
# $FileBrowser = New-Object System.Windows.Forms.OpenFileDialog -Property @{ InitialDirectory = [Environment]::GetFolderPath('Desktop') }
# $null = $FileBrowser.ShowDialog()

# clear-host
# $trimpath = "$env:USERPROFILE\trim.txt"
# $resultpath = "$env:USERPROFILE\result.csv"
# $file = Get-Content $FileBrowser.FileName 
# $file = $file |Out-String
# $file.Trim() |Set-Content $trimpath
# $users = Get-Content $trimpath
# $results = @()


# foreach($user in $users){

#     $Password= New-RandomizedPassword -PasswordLength 12 -RequiresUppercase $true -RequiresNumerical $true 
#     $NewPwd = ConvertTo-SecureString $Password-AsPlainText -Force
#     # Set-ADAccountPassword $user -NewPassword $NewPwd -Reset
#     # Set-ADUser -Identity $user -ChangePasswordAtLogon $true
#     $results += write-output "$user,$password"
#     write-host  $user -foregroundcolor Cyan -NoNewline; write-host "" $Password-foregroundcolor Green
#     Start-Sleep 1
# }

# Write-Output "SAM,PASSWORD" |Out-File -FilePath $resultpath  #Header for CSV

# $results | out-file -FilePath $resultpath -Append
# #Read-host -Prompt "Press enter to exit"    