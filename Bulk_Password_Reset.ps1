<# 
 Author Alif Amzari Mohd Azamee
 Contain forked function 'New-RandomizedPassword' courtesy from William Ogle. Function has been modified to exclude certain ambiguous (hard to see) character such as O,0,o,l,I,1. 
 Contain forked function 'Send-SDMail 
 Contain external function Get-PSWho, Get-PDC
#>
Import-Module ActiveDirectory
$PsWho = $env:USERNAME
Function Write-Log {
  Param(
    [Parameter(Position = 0)] [string]$File,
    [Parameter(Position = 2)] [string]$Who,
    [Parameter(Position = 3)] [string]$Data,
    [Parameter(Position = 4)] [string]$Level
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
  
} #End Function

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
    $Mail,
    [String]
    $Username,
    [String]
    $FullName,
    [String]
    $ManagerFullName,
    [String]
    $PwdToMgr,
    [String]
    $PwdToUsr,
    [String]
    $LogFile
  )
  $PAMUsername = $Username
  $Username = $PAMUsername.Substring(3)
  $MailTempPasswordSubject = "Temporary de-prod.dk password  for ##Fullname##"
  $MailTempPasswordText = "Hi ##ManagerFullname##, <BR><BR>This is the temporary password for the account belonging to ##Username##: ##Password##<BR><BR>Please make sure to hand-over the password to the user." 
  [Array]$MailAttachments = $null
  Write-Host "Sending mail"
  $To = $Mail
  $From = "Ørsted SD AAC <SD_Assistance@orsted.com>"
  If ($PwdToMgr) {
    Write-Log $LogFile "Sending mail with password to $Mail"
    $Subject = $MailTempPasswordSubject -replace('##FullName##',$FullName)
    $Body = $MailTempPasswordText -replace('##ManagerFullName##',$ManagerFullName) -replace('##UserName##',$UserName) -replace('##Password##',$Password) 
  }
    Elseif ($PwdToUsr) {
      Write-Log $LogFile "Sending mail with the temporary password to $Mail"
      $Subject = "Password for de-prod.dk"
      $Body = "Dear $FullName,<BR><BR>This is your temporary password: $PwdToUsr<BR><BR>You cannot reply to this email.<BR><BR>Kind regards"

      $SMTPServer = "gwsmtp-07.de-prod.dk"
      If ($MailAttachments -eq $Null) {
        Send-MailMessage -To $To -From $From -Subject $Subject -Body $Body -BodyAsHtml -Encoding unicode -SmtpServer $SMTPServer
        } 
        Else {
          Send-MailMessage -To $To -From $From -Subject $Subject -Body $Body -BodyAsHtml -Encoding Unicode -SmtpServer $SMTPServer -Attachments $MailAttachments -Verbose
        }  
    } 
} #End Send-SDMail

write-host "Expecting input file..."
Start-sleep 2
Add-Type -AssemblyName System.Windows.Forms
$FileBrowser = New-Object System.Windows.Forms.OpenFileDialog -Property @{ InitialDirectory = [Environment]::GetFolderPath('Desktop') }
$null = $FileBrowser.ShowDialog()

clear-host
$trimpath = "$env:USERPROFILE\trim.txt"
$resultpath = "$env:USERPROFILE\result.csv"
$file = Get-Content $FileBrowser.FileName 
$file = $file |Out-String
$file.Trim() |Set-Content $trimpath
$users = Get-Content $trimpath
$results = @()

Function Reset-DeprodPwd {
    [CmdletBinding()]
    param (
        [Paramater()]
        [string]
        $Username
        )
        Write-Host "Retrieving PDC for de-prod.dk"
        ]$DC = Get-PDC -DomainName de-prod.dk
        Write-Host "Using $($DC.HostName) as DC for the de-prod.dk domain"
        $CurrentUser = (Get-Pswho).Username
        Write-host "Locating $Username"
        $AccountExists = $False
        try {
            $IfUserExist = Get-ADUser $Username -Properties Givenname,Surname -Server $DC -ErrorAction Stop
            $ManagerEmail = (Get-ADUser $Username -Properties *| Select-Object Displayname, @{Name="ManagerEmail";Expression={(get-aduser -property emailaddress $_.manager).emailaddress}}).ManagerEmail
            if ($IfUserExist) {
                $AccountExists = $true
                $PasswordReset = $true
                $Password= New-RandomizedPassword -PasswordLength 12 -RequiresUppercase 1 -RequiresNumerical 1
                $SecPass = ConvertTo-SecureString $Password-AsPlainText -Force
                try {
                    $PasswordReset = $true
                    Write-Verbose "Trying to reset password for $Username"
                    Set-ADAccountPassword -Identity $Username -NewPassword $SecPass -ErrorAction Stop
                    Set-ADUser -Identity $Username -ChangePasswordAtLogon $true
                    $Fullname = $IfUserExist.Givenname + " " + $IfUserExist.surname
                    $Mail = $ManagerEmail
                }
                catch {
                    $PasswordReset = $False
                }
                Finally {
                    if ($PasswordReset -eq $true) {
                        Write-Verbose "Password for $Username reset"
                    }
                    else {
                        Write-Verbose "Error:Password for $Username failed to reset"
                    }
                }

            <# Action to perform if the condition is true #>
            }

}

} #end Reset-DeprodPwd
foreach($user in $users){

    $Password= New-RandomizedPassword -PasswordLength 12 -RequiresUppercase 1 -RequiresNumerical 1 
    $NewPwd = ConvertTo-SecureString $Password-AsPlainText -Force
    # Set-ADAccountPassword $user -NewPassword $NewPwd -Reset
    # Set-ADUser -Identity $user -ChangePasswordAtLogon $true
    $results += write-output "$user,$password"
    write-host  $user -foregroundcolor Cyan -NoNewline; write-host "" $Password-foregroundcolor Green
    Start-Sleep 1
}

Write-Output "SAM,PASSWORD" |Out-File -FilePath $resultpath  #Header for CSV

$results | out-file -FilePath $resultpath -Append
#Read-host -Prompt "Press enter to exit"    