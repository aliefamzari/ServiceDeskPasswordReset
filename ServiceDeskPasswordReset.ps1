<# 
 Author Alif Amzari Mohd Azamee
 Azure DevOps Project URL: https://dev.azure.com/ALMAZ0773/ServiceDesk%20Password%20Reset
 Contain forked function 'New-RandomizedPassword' courtesy from William Ogle. Function has been modified to exclude certain ambiguous (difficult to read) character such as O,0,o,l,I,1. 
 Contain forked function 'Send-SDMail,Get-PDC'
 Encoding = ANSI (Windows 1252)
#>

#Region GlobalVariable Read from config.json
$ScriptPath = split-path -parent $MyInvocation.MyCommand.Definition
$Config = (Get-Content -Path $ScriptPath\config.json) |ConvertFrom-Json
$LogPath = "$env:USERPROFILE\ServiceDeskPasswordReset.log"
$MailSender = $Config.MailSender
$SMTPServer = $Config.SmtpServer
$DomainName = $Config.DomainName
$ChangePasswordAtLogon = $Config.ChangePasswordAtLogon
$OrgName = $Config.OrgName
$SMSAddress = $Config.SMSAddress
$DisplayPasswordOnScreen = $Config.DisplayPasswordOnScreen
#Endregion GlobalVariable

#Region Import Active-Directory Module
Try {
  Import-Module ActiveDirectory -ErrorAction Stop
}
Catch {
  Write-Host "Error Importing module ActiveDirectory"
  Break
}
#Endregion Import Active-Directory Module

Function Get-AdmCred {

  $AdmUsername = read-host "Enter your ADM username (admxxxxx)" -
  $AdmPassword =  read-host  "Enter your ADM password" -AsSecureString -
  $AdmCredential = New-Object System.Management.Automation.PSCredential -ArgumentList $AdmUsername, $AdmPassword -ErrorAction SilentlyContinue
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
        Write-Host "PDC could not be found for $DomainName" -ForegroundColor Red 
        Write-log -level Error -Data "PDC could not be found for $DomainName"
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
        Write-log -level Error -Data "PDC could not be found for $DomainName"
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
            # These are the characters !#$%&+?@
            $null = $PasswordCharacterArray.Add(((33,35,36,37,38,43,63,64) | Get-Random | ForEach-Object {[char]$_}))
            $PasswordLength = $PasswordLength - 1
            $null = $CharacterSpaceArray.Add((33,35,36,37,38,43,63,64))
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
  $MailSubject = Get-Content $ScriptPath\MailSubject.txt
  $MailSubjectManager = $MailSubject[1]
  $MailSubjectSmS = $MailSubject[3]
  $MailSubjectUser = $MailSubject[5]
  $MailBody = Get-Content $ScriptPath\MailBody.html -Raw
  $MailBodySMS = Get-Content $ScriptPath\MailBodySMS.html -Raw
  $MailBodyUser = Get-Content $ScriptPath\MailBodyUser.html -Raw
  $From = $MailSender
  # Write-Output "Sending mail" |Write-Log -Level Info 
  Switch ($SendPwdTo) {     
   Manager {
    $Subject = $MailSubjectManager -replace('FullName',$FullName) -replace('DomainName',$DomainName)
    $Body = $MailBody -replace('ManagerFullName',$ManagerFullName) -replace('FullName',$FullName) -replace('Passwd',$Passwd)
   }
   User {
    $Subject = $MailSubjectUser -replace('FullName',$FullName) -replace('DomainName',$DomainName)
    $Body = $MailBodyUser -replace('FullName',$FullName)
   }
   SMS {
    $Subject = $MailSubjectSmS -replace('FullName',$FullName) -replace('DomainName',$DomainName)
    $Body = $MailBodySMS -replace('FullName',$FullName) -replace('Passwd',$Passwd)
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

Function Get-UserType {
  [CmdletBinding()]
  param(
      [Parameter()]
      [String]
      $UserName,
      [String]
      $DC,
      [bool]
      $PR
      )


  try {
      $ADUser = get-aduser $UserName -server $DC -Properties memberof,userprincipalname,Givenname,Surname,Manager,Enabled,mobilephone,mail,msDS-UserPasswordExpiryTimeComputed,lockedout,title,department,division,employeenumber,office,country,PasswordExpired,PasswordLastSet -ErrorAction Stop
      $Enabled = $ADUser.Enabled
      $Sam = $ADuser.SAMAccountName
      $Fullname = $ADUser.givenname + " " + $ADUser.surname
      $Manager = $ADUser.Manager
      $ADUserEmail = $ADUser.mail
      $mobilephone = $ADUser.mobilephone
      $LockedOut = $ADUser.lockedout
      $Country = $ADUser.country
      $Title = $ADUser.title
      $Department = $ADUser.department
      $EmployeeNumber = $ADUser.employeenumber
      $Office = $ADUser.office
      $UserPrincipalName = $ADUser.userprincipalname
      $PasswordExpired = $ADUser.PasswordExpired
      $PasswordLastSet =  $ADUser.PasswordLastSet
      $PassworDaysLeft = (([datetime]::FromFileTime($ADuser.'msDS-UserPasswordExpiryTimeComputed'))-(Get-Date)).Days
      $isADM = $aduser.memberof.Contains('CN=ADM Accounts,OU=Specielle Konti,OU=DE-PROD.DK,DC=de-prod,DC=dk')
      $AccountExist = $true

  }
  catch {
      $AccountExist = $false
  }
  #Region CheckPhone
  if ($MobilePhone) {
      $MobilePhoneisExist = $true
  }
  else {
      $MobilePhoneisExist = $false
  }
  #EndRegion CheckPhone

  #Region Check-Manager
  if($manager) {
      $Manager = Get-ADuser $manager -server $DC -Properties mail,givenname,surname -ErrorAction Stop
      $ManagerEmail = $Manager.mail
      $ManagerFulLName = $Manager.givenname + " " + $Manager.Surname
      $ManagerExist = $true
  }
  else {
      $ManagerExist = $false
  }
  #EndRegion Check-Manager

  #Region User Type Matrix
   <#
    +-----------+-----------+--------------+------------------+----------------+
    | User Type | IsEnabled | ManagerExist | MobilePhoneExist | Password Reset |
    +-----------+-----------+--------------+------------------+----------------+
    | 1         | y         | y            | y                | y              |
    | 2         | y         | y            | n                | y              |
    | 3         | y         | n            | y                | y              |
    | 4         | y         | n            | n                | n              |
    | 5         | n         | n            | n                | n              |
    | 6         | n         | y            | n                | n              |
    | 7         | n         | n            | y                | n              |
    | 8         | n         | y            | y                | n              |
    | 9         | n         | n            | n                | n              |
    | 10        | na        | na           | na               | n              |
    +-----------+-----------+--------------+------------------+----------------+
   #>
   $type1 = ($Enabled -and $ManagerExist -and $MobilePhoneisExist -and $AccountExist) 
   $type2 = ($Enabled -and $ManagerExist -and !$MobilePhoneisExist -and $AccountExist)
   $type3 = ($Enabled -and !$ManagerExist -and $MobilePhoneisExist -and $AccountExist)
   $type4 = ($Enabled -and !$ManagerExist -and !$MobilePhoneisExist -and $AccountExist)
   $type5 = (!$Enabled -and !$ManagerExist -and !$MobilePhoneisExist -and $AccountExist)
   $type6 = (!$Enabled -and $ManagerExist -and !$MobilePhoneisExist -and $AccountExist)
   $type7 = (!$Enabled -and !$ManagerExist -and $MobilePhoneisExist -and $AccountExist)
   $type8 = (!$Enabled -and $ManagerExist -and $MobilePhoneisExist -and $AccountExist)
   $type9 = (!$AccountExist)
   $type10 = ($isADM)
  #EndRegion User Type Matrix
  switch ($true) {
      $type1 { 
          $PR = $true
          $type = 1
          }
      $type2 {
          $PR = $true
          $type = 2
          }
      $type3 {
          $PR = $true
          $type = 3
          }
      $type4 { 
          $PR = $false
          $type = 4
      }
      $type5 { 
          $PR = $false
          $type = 5
      }
      $type6 { 
          $PR = $false
          $type = 6
      }
      $type7 { 
          $PR = $false
          $type = 7
      }
      $type8 { 
          $PR = $false
          $type = 8
      }
      $type9 { 
          $PR = $false
          $type = 9
      }
      $type10 { 
          $PR = $false
          $type = 10
    }
  }
  $Object = New-Object PSCustomObject 
  $Object | Add-Member -MemberType NoteProperty -Name "Type" -Value $type
  $Object | Add-Member -MemberType NoteProperty -Name "isADM" -Value $isADM
  $Object | Add-Member -MemberType NoteProperty -Name "isEnabled" -Value $Enabled
  $Object | Add-Member -MemberType NoteProperty -Name "Sam" -Value $Sam
  $Object | Add-Member -MemberType NoteProperty -Name "FullName" -Value $Fullname
  $Object | Add-Member -MemberType NoteProperty -Name "Mail" -Value $ADUserEmail
  $Object | Add-Member -MemberType NoteProperty -Name "UserPrincipalName" -Value $UserPrincipalName
  $Object | Add-Member -MemberType NoteProperty -Name "MobilePhone" -Value $mobilephone
  $Object | Add-Member -MemberType NoteProperty -Name "Manager" -Value $Manager
  $Object | Add-Member -MemberType NoteProperty -Name "ManagerEmail" -Value $ManagerEmail
  $Object | Add-Member -MemberType NoteProperty -Name "ManagerFullName" -Value $ManagerFulLName
  $Object | Add-Member -MemberType NoteProperty -Name "PasswordisReset" -Value $PR
  $Object | Add-Member -MemberType NoteProperty -Name "AccountExist" -Value $AccountExist
  $Object | Add-Member -MemberType NoteProperty -Name "PasswordDaysLeft" -Value $PassworDaysLeft
  $Object | Add-Member -MemberType NoteProperty -Name "PasswordExpired" -Value $PasswordExpired
  $Object | Add-Member -MemberType NoteProperty -Name "PasswordLastSet" -Value $PasswordLastSet
  $Object | Add-Member -MemberType NoteProperty -Name "LockedOut" -Value $LockedOut
  $Object | Add-Member -MemberType NoteProperty -Name "Country" -Value $Country
  $Object | Add-Member -MemberType NoteProperty -Name "EmployeeNumber" -Value $employeenumber
  $Object | Add-Member -MemberType NoteProperty -Name "Title" -Value $Title
  $Object | Add-Member -MemberType NoteProperty -Name "Office" -Value $Office
  $Object | Add-Member -MemberType NoteProperty -Name "Department" -Value $Department



  $Object
}#end Get-UserType

Function Reset-AdPwd {
  [CmdletBinding()]
  param(
        [Parameter()]
        [String]
        $UserName,
        [String]
        [Parameter()]
        [ValidateSet("Manager","SMS","User","ManagerSMSUser","Bulk")]
        $MailTo,
        [Parameter(Mandatory=$false)]
        [Int]$PasswordLength = 12
        )

        $StartTime = get-date #Start stopwatch
        Write-Host "Retrieving PDC for $DomainName"
        $DC = Get-PDC -DomainName $DomainName
        Write-Host "Using $($DC.HostName) as DC for the $DomainName domain"
        Write-host "Querying $Username in Active-Directory"

        #Region Get-UserType
        $TUser = (Get-UserType -UserName $username -dc $dc)
        $Type = $TUser.Type
        $Mobilephone = $TUser.mobilephone
        $PasswordisReset = $TUser.$PasswordisReset
        $Manager = $TUser.manager
        $ADUserEmail = $TUser.Mail
        $AccountExist = $Tuser.AccountExist
        $FullName = $TUser.FullName
        $ManagerFulLName = $TUser.ManagerFullName
        $ManagerEmail = $TUser.ManagerEmail
        Write-Host "[$Username]User is Type $type"
        Write-log -Level Info -Data "[$Username]User is Type $type"
        #EndRegion Get-UserType

        switch ($type -match '[1-3]') {
            $True {
                $Password = New-RandomizedPassword -PasswordLength $PasswordLength -RequiresUppercase $true -RequiresNumerical $true -RequiresSpecial $true
                $SecPass = ConvertTo-SecureString $Password -AsPlainText -Force
                try {
                    Write-Host "[$Username]Reseting password"
                    $PasswordisReset = $true
                    Set-ADAccountPassword -Identity $UserName -Server $DC -NewPassword $SecPass -Credential $AdmCredential -ErrorAction Stop
                    if ($ChangePasswordAtLogon -eq '$true') {
                    Set-ADUser -Identity $Username -Server $dc -ChangePasswordAtLogon $true -Credential $AdmCredential -ErrorAction Stop
                    }
                    else {
                    Set-ADUser -Identity $Username -Server $dc -ChangePasswordAtLogon $false -Credential $AdmCredential -ErrorAction Stop
                    }
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
                        write-host "catch"
                    }
            }
        }

        switch ($Type) {
            4 {
                Write-Host "[$Username]Manager is Empty"
                Write-Host "[$Username]Mobilephone is empty"
                $PasswordisReset = $false
            }
            5 {
                Write-host "[$Username]Manager is Empty"
                Write-Host "[$Username]Mobilephone is empty"
                Write-Host "[$Username]Account is Disabled" -ForegroundColor Yellow
                $PasswordisReset = $false
            }
            6 {
                write-host "[$Username]Manager is $ManagerFulLName. Email is $ManagerEmail"
                Write-Host "[$Username]Mobilephone is empty"
                Write-Host "[$Username]Account is Disabled" -ForegroundColor Yellow
                $PasswordisReset = $false
            }
            7 {
                Write-Host "[$Username]Manager is Empty"
                Write-Host "[$Username]Mobilephone is $Mobilephone"
                Write-Host "[$Username]Account is Disabled" -ForegroundColor Yellow
                $PasswordisReset = $false
            }
            8 {
                write-host "[$Username]Manager is $ManagerFulLName. Email is $ManagerEmail"
                Write-Host "[$Username]Mobilephone is $Mobilephone"
                Write-Host "[$Username]Account is Disabled" -ForegroundColor Yellow
                $PasswordisReset = $false
            }
            9 {
                Write-Host "[$Username]Account is not exist" -ForegroundColor Yellow
                $PasswordisReset = $false
            }
            10 {
              Write-Host "[$Username]ADM Account - refer PAM" -ForegroundColor Yellow
              $PasswordisReset = $false
            }
        }
          #Region Send Function
          function SendMgr {
            if ($PasswordisReset -eq $true) {
            # $To =  "almaz@orsted.com"
            $To = $ManagerEmail
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
            }

          } #End SendMgr
          function SendSMS {
                  $To = $mobilephone.Replace(" ","")
                  $To = $To + $SMSAddress
                  # $To = '+60124364147@sms.orsted.com'
                  Write-Host "[$Username]Sending SMS Password to $mobilephone.."
                  Send-SDMail -To $To -UserName $Username -FullName $Fullname -ManagerFullName $ManagerFulLName -SendPwdTo SMS -Passwd $Password
                  write-host "[$Username]SMS password sent to $To"
                  Write-Log -Level Info -Data "[$Username]SMS password sent to $To"
          } #End SendSMS

          function SendUsr {
                if ($PasswordisReset -eq $true) {
                $To = $ADUserEmail
                # $To = 'almaz@orsted.com'
                # $FullName = $ADUser.GivenName + " " + $ADUser.surname
                Write-Host "[$Username]Sending notification mail to $ADUserEmail.."
                Send-SDMail -to $To -FullName $FullName -SendPwdTo User
                Write-Host  "[$Username]Notification mail sent to $To"
                Write-Log -Level Info -Data "[$Username]Notification mail sent to $to"
                }
          } #End SendUsr
          #EndRegion Send Function

        switch ($PasswordisReset) {
            True {
                Write-Host "[$Username]Password is reset" -ForegroundColor Cyan
                Write-log -level info -data "[$Username]Password is reset"
                if ($DisplayPasswordOnScreen -eq '$true') {
                    Write-host "[$Username]Password is: "-NoNewline 
                    Write-host "$Password" -ForegroundColor Cyan
                }
                switch ($type) {
                    1 {
                      Switch ($MailTo) {
                        '' {
                            Write-Host "[$Username]Callback $mobilephone"
                            Write-log -level info -data "[$Username]Callback $mobilephone"

                        }
                        SMS {
                          # $MailTo = SMS
                          Write-Host "[$Username]Callback $mobilephone"
                          Write-log -level info -data "[$Username]Callback $mobilephone"
                          SendUsr
                        }
                        Manager {
                          # $Mailto = Manager
                          SendUsr
                        }

                        # ManagerSMSUser{
                        #   $MailTo =  ManagerSMSUser
                        # }
                        Bulk {
                          $MailTo = 'Manager'
                        }
                  
                        
                      }
                    }
                    2 { 
                          switch ($mailto) {
                            '' {
                                Write-Host "[$Username]Mobilephone is empty. Sending to Manager instead"
                                Write-Log -level Warning -Data "[$Username]Mobilephone is empty. Sending to Manager instead"
                                $mailto = 'manager'
                                SendUsr
                                }
                            ManagerSMSUser {
                                Write-Host "[$Username]Mobilephone is empty. Sending to Manager instead"
                                Write-Log -level Warning -Data "[$Username]Mobilephone is empty. Sending to Manager instead"
                                $mailto = 'manager'
                                SendUsr
                                }
                            SMS {
                                Write-Host "[$Username]Mobilephone is empty. Sending to Manager instead"
                                Write-Log -level Warning -Data "[$Username]Mobilephone is empty. Sending to Manager instead"
                                $mailto = 'manager'
                                SendUsr
                                }
                            Manager {
                                $mailto = 'manager'
                                SendUsr
                                }
                            Bulk {
                                $MailTo = 'manager'
                                }
                        }
                    }
                    3 { 
                      switch ($MailTo) {
                        '' {  
                          Write-Host "[$Username]Callback $mobilephone"
                          Write-log -level info -data "[$Username]Callback $mobilephone"
                        }
                        ManagerSMSUser{
                          Write-Host "[$Username]Callback $mobilephone"
                          Write-log -level info -data "[$Username]Callback $mobilephone"
                          Write-host "Manager not exist. Sending to SMS instead.."
                          $mailto = 'SMS'
                          SendUsr

                        }
                        SMS {
                          $mailto = 'SMS'
                          SendUsr
                        }
                        Manager {
                          Write-Host "[$Username] Callback $mobilephone"
                          Write-log -level info -data "[$Username]Callback $mobilephone"
                          Write-host "Manager not exist. Sending to SMS instead.."
                          $mailto = 'SMS'
                          SendUsr
                        }
                        Bulk {
                          Write-Host "[$Username]Password reset. But not send" -ForegroundColor Yellow
                          write-log -Level Warning -data "[$Username]Password reset. But not send"
                          Write-Host "[$Username]Manager is empty" -ForegroundColor Yellow
                          write-log -Level Warning -Data "[$Username]Manager is empty" 
                        }
                      }
                    }
                }
        
            }
            false {
                write-host "[$Username]Error:Password not reset" -ForegroundColor Red
                Write-log -level Error -data "[$Username]Password not reset"
            }
        }


        switch ($MailTo) {
            Manager { if ($PasswordisReset -and $type -match '[1-2]') {
                    SendMgr
                    }
        
            }
            SMS { if ($PasswordisReset -and $type -ne '2') {
                    SendSMS
                    }
        
            }
            User { if ($PasswordisReset) {
                    SendUsr
                    }
            }

            ManagerSMSUser { if ($PasswordisReset) {
                    SendMgr
                    SendSMS
                    SendUsr
                    }

            }
            Bulk { if ($PasswordisReset) {
                    SendMgr
                    }

            }
        }

        $RunTime = New-TimeSpan -Start $StartTime -End (get-date)  #End Stop Watch
        "Execution time was {0}:{1}:{2}.{3}" -f $RunTime.Hours,  $RunTime.Minutes,  $RunTime.Seconds,  $RunTime.Milliseconds 
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
      Write-Host "Overriding DisplayPasswordONscreen to $FALSE" -ForegroundColor Yellow


    foreach ($item in $users){
      try {     

            if ($PasswordLength -eq 0){
              Write-host "Attempting to reset for user $item"
              Reset-AdPwd -Username $item -MailTo Bulk
            }
            else {
              Write-host "Attempting to reset for user $item"
              Reset-AdPwd -Username $item -PasswordLength $PasswordLength -MailTo Bulk
            }
          }
      catch [System.Security.Authentication.AuthenticationException],[System.UnauthorizedAccessException]{
        Write-Host "Authentication Error. Check your credentianls" -ForegroundColor Red
        Write-log -Level Error -Data "Authentication Error. Check your credentials" 
      }
    }
  }
} #end Reset-PwdMulti

Function Show-SDPasswdResetMenu {
  clear-host
  $pswho = $env:USERNAME
  $TitleColor = "White"
  $MenuTitleColor = "Cyan"
  $ItemNumberColor = "Cyan"
  $ItemTextColor = "White"
  $ItemWarningColor = "Yellow"
  Write-Host "Enter your admin account for Active Directory. This will be use as the credentials to perform password reset." -ForegroundColor Cyan
  $AdmCredential = Get-AdmCred
 
  

  While ($Menu -ne '') {
      Clear-Host
      Write-Host -ForegroundColor $TitleColor "`n`t`t $OrgName Service Desk Password Reset Tool`n"
      Write-Host -ForegroundColor $ItemTextColor "Welcome $pswho"
      Write-Host -ForegroundColor $MenuTitleColor "`n[Main Menu]" 
      Write-Host -ForegroundColor $ItemTextColor -NoNewline "`n["; Write-Host -ForegroundColor $ItemNumberColor -NoNewline "1"; Write-Host -ForegroundColor $ItemTextColor -NoNewline "]"; `
      Write-Host -ForegroundColor $ItemTextColor " Reset password for a user. [Send SMS and Callback]"
      Write-Host -ForegroundColor $ItemTextColor -NoNewline "`n["; Write-Host -ForegroundColor $ItemNumberColor -NoNewline "2"; Write-Host -ForegroundColor $ItemTextColor -NoNewline "]"; `
      Write-Host -ForegroundColor $ItemTextColor " Reset password for a user. Password send to Manager"
      Write-Host -ForegroundColor $ItemTextColor -NoNewline "`n["; Write-Host -ForegroundColor $ItemNumberColor -NoNewline "3"; Write-Host -ForegroundColor $ItemTextColor -NoNewline "]"; `
      Write-Host -ForegroundColor $ItemTextColor " Reset password for multiple user. Password send to manager via email.(Format CSV with line breaks delimiter)."
      Write-Host
      Write-Host "Current Settings config.json"
      write-host "----------------------------"
      if ($DisplayPasswordOnScreen -eq '$true') {
        Write-Host "DisplayPasswordOnScreen : "-NoNewline
        Write-Host "ON" -ForegroundColor DarkGreen
      }
      else {
        Write-Host "DisplayPasswordOnScreen : "-NoNewline
        Write-Host "OFF" -ForegroundColor Red
      }
      if ($ChangePasswordAtLogon -eq '$true') {
        Write-Host "ChangePasswordAtLogon : "-NoNewline
        Write-Host "ON" -ForegroundColor DarkGreen
      }
      else {
        Write-Host "ChangePasswordAtLogon : "-NoNewline
        Write-Host "OFF" -ForegroundColor Red
      }
      # Write-Host "Dommain Name : $DomainName"
      # Write-Host "Organization Name : $OrgName"
      # Write-Host "SMTP Server : $SMTPServer"
      # Write-host "Mail Sender : $MailSender"
      # Write-Host "Log Path : $LogPath"
      
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
              Reset-AdPwd -Username $Username -MailTo Manager
            }
            else {
              Write-Host "Password Length is $PasswordLength"
              Reset-AdPwd -Username $Username -PasswordLength $Passwordlength -MailTo Manager
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

