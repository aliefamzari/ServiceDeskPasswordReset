# Author Alif Amzari @orsted
# Contain function 'New-RandomizedPassword' courtesy from William Ogle. Function has been modified to exclude certain ambiguous (hard to see) character such as O,0,o,l,I,1. 
# To-Do :  Error handling and log output

Import-Module ActiveDirectory

function New-RandomizedPassword
{
    [CmdletBinding()]
    param (
        # Number of characters in password, defaults to 8
        [Parameter(Mandatory=$false)]
        [ValidateRange(6, 64)]
        [Int]$PasswordLength = 8,


        # Is at least 1 uppercase character required for password? Defaults to false
        [Parameter(Mandatory = $false)]
        [bool]$RequiresUppercase = $false,


        # Is at least 1 numerical character required for password? Defaults to false
        [Parameter(Mandatory = $false)]
        [bool]$RequiresNumerical = $false,


        # Is at least 1 special character required for password? Defaults to false
        [Parameter(Mandatory = $false)]
        [bool]$RequiresSpecial = $false
    )


    [string]$Password = ""


    if (($RequiresUppercase -eq $true) -and ($RequiresNumerical -eq $true) -and ($RequiresSpecial -eq $true))
    {
        $Password += ((65..72),(74..78),(80..90) | Get-Random | ForEach-Object {[char]$_}) # Add an uppercase character. Excluded 'I' and 'O'
        $Password += ((50..57) | Get-Random | ForEach-Object {[char]$_}) # Add a number. Excluded '0 and 1'
        $Password += ((33..38) + (40..47) + (58..64) | Get-Random | ForEach-Object {[char]$_}) # Add a special character
        $Password += ((97..107),(109,110),(112..122) | Get-Random | ForEach-Object {[char]$_}) # Add a lowercase character. Excluded 'l' and 'o'


        for($i = 1; $i -le ($PasswordLength - 4); $i++)
        {
            $Password += ((33..38) + (40..47) + (58..64) + (65..72),(74..78),(80..90) + (50..57) + (97..107),(109,110),(112..122) | Get-Random | ForEach-Object {[char]$_})
        }
    }
    elseif (($RequiresUppercase -eq $true) -and ($RequiresNumerical -eq $true) -and ($RequiresSpecial -eq $false))
    {
        $Password += ((65..72),(74..78),(80..90) | Get-Random | ForEach-Object {[char]$_}) # Add an uppercase character. Excluded 'I' and 'O'
        $Password += ((50..57) | Get-Random | ForEach-Object {[char]$_}) # Add a number. Excluded '0 and 1'
        $Password += ((97..107),(109,110),(112..122) | Get-Random | ForEach-Object {[char]$_}) # Add a lowercase character. Excluded 'l' and 'o'


        for($i = 1; $i -le ($PasswordLength - 3); $i++)
        {
            $Password += ((65..72),(74..78),(80..90) + (50..57) + (97..107),(109,110),(112..122) | Get-Random | ForEach-Object {[char]$_})
        }
    }
    elseif (($RequiresUppercase -eq $true) -and ($RequiresNumerical -eq $false) -and ($RequiresSpecial -eq $true))
    {
        $Password += ((65..72),(74..78),(80..90) | Get-Random | ForEach-Object {[char]$_}) # Add an uppercase character. Excluded 'I' and 'O'
        $Password += ((33..38) + (40..47) + (58..64) | Get-Random | ForEach-Object {[char]$_}) # Add a special character
        $Password += ((97..107),(109,110),(112..122) | Get-Random | ForEach-Object {[char]$_}) # Add a lowercase character. Excluded 'l' and 'o'


        for($i = 1; $i -le ($PasswordLength - 3); $i++)
        {
            $Password += ((33..38) + (40..47) + (58..64) + (65..72),(74..78),(80..90) + (97..107),(109,110),(112..122) | Get-Random | ForEach-Object {[char]$_})
        }
    }
    elseif (($RequiresUppercase -eq $true) -and ($RequiresNumerical -eq $false) -and ($RequiresSpecial -eq $false))
    {
        $Password += ((65..72),(74..78),(80..90) | Get-Random | ForEach-Object {[char]$_}) # Add an uppercase character. Excluded 'I' and 'O'
        $Password += ((97..107),(109,110),(112..122) | Get-Random | ForEach-Object {[char]$_}) # Add a lowercase character. Excluded 'l' and 'o'


        for($i = 1; $i -le ($PasswordLength - 2); $i++)
        {
            $Password += ((65..72),(74..78),(80..90) + (97..107),(109,110),(112..122) | Get-Random | ForEach-Object {[char]$_})
        }
    }
    elseif (($RequiresUppercase -eq $false) -and ($RequiresNumerical -eq $true) -and ($RequiresSpecial -eq $true))
    {
        $Password += ((50..57) | Get-Random | ForEach-Object {[char]$_}) # Add a number. Excluded '0 and 1'
        $Password += ((33..38) + (40..47) + (58..64) | Get-Random | ForEach-Object {[char]$_}) # Add a special character
        $Password += ((97..107),(109,110),(112..122) | Get-Random | ForEach-Object {[char]$_}) # Add a lowercase character. Excluded 'l' and 'o'


        for($i = 1; $i -le ($PasswordLength - 3); $i++)
        {
            $Password += ((33..38) + (40..47) + (58..64) + (50..57) + (97..107),(109,110),(112..122) | Get-Random | ForEach-Object {[char]$_})
        }
    }
    elseif (($RequiresUppercase -eq $false) -and ($RequiresNumerical -eq $true) -and ($RequiresSpecial -eq $false))
    {
        $Password += ((50..57) | Get-Random | ForEach-Object {[char]$_}) # Add a number. Excluded '0 and 1'
        $Password += ((97..107),(109,110),(112..122) | Get-Random | ForEach-Object {[char]$_}) # Add a lowercase character. Excluded 'l' and 'o'


        for($i = 1; $i -le ($PasswordLength - 2); $i++)
        {
            $Password += ((50..57) + (97..107),(109,110),(112..122) | Get-Random | ForEach-Object {[char]$_})
        }
    }
    elseif (($RequiresUppercase -eq $false) -and ($RequiresNumerical -eq $false) -and ($RequiresSpecial -eq $false))
    {
        for($i = 1; $i -le $PasswordLength; $i++)
        {
            $Password += ((97..107),(109,110),(112..122) | Get-Random | ForEach-Object {[char]$_})
        }
    }
    elseif (($RequiresUppercase -eq $false) -and ($RequiresNumerical -eq $false) -and ($RequiresSpecial -eq $true))
    {
        $Password += ((33..38) + (40..47) + (58..64) | Get-Random | ForEach-Object {[char]$_}) # Add a special character
        $Password += ((97..107),(109,110),(112..122) | Get-Random | ForEach-Object {[char]$_}) # Add a lowercase character. Excluded 'l' and 'o'


        for($i = 1; $i -le ($PasswordLength - 4); $i++)
        {
            $Password += ((33..38) + (40..47) + (58..64) + (97..107),(109,110),(112..122) | Get-Random | ForEach-Object {[char]$_})
        }
    }
    $CharacterArray = $Password.ToCharArray()
    $ScrambledCharacterArray = $CharacterArray | Get-Random -Count $CharacterArray.Length
    return -join $ScrambledCharacterArray
}

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


 foreach($user in $users){

    $Password = New-RandomizedPassword -PasswordLength 12 -RequiresUppercase 3 -RequiresNumerical 2 
    $NewPwd = ConvertTo-SecureString $Password -AsPlainText -Force
    # Set-ADAccountPassword $user -NewPassword $NewPwd -Reset
    # Set-ADUser -Identity $user -ChangePasswordAtLogon $true
    $results += write-output "$user,$password"
    write-host  $user -foregroundcolor Cyan -NoNewline; write-host "" $Password -foregroundcolor Green
    Start-Sleep 1
}

Write-Output "SAM,PASSWORD" |Out-File -FilePath $resultpath  #Header for CSV

$results | out-file -FilePath $resultpath -Append
#Read-host -Prompt "Press enter to exit"    