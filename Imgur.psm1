<#
# Imgur Upload - Created by -Kai {https://kai.wtf/social}
# Created 22nd November, 2019
#
# Imgur API Reference: https://apidocs.imgur.com/?version=latest
#>

<#~ Variables that are set by script functions ~#>

<# Path that the image is uploaded from (Your computer) Example: C:/Users/Kai/Desktop/AmazingFile.png #>
$script:FilePath = $null
<# Your IMGUR ClientID ~ https://api.imgur.com/oauth2/addclient #>
$script:ClientID = $null
<# Name of account when using OAuth2 #>
$script:Account_Username = $null
$script:Account_ID = $null
<# OAuth2 Token data - from Connect-ImgurOAuth2 #>
$script:Access_Token = $null
$script:Refresh_Token = $null
$script:Token_Type = $null
$script:Token_Expire = $null
<# URL of the image that is successfully uploaded to Imgur #>
$script:URL = $null
<# DeleteHash of the image that is successfully uploaded to Imgur #>
$script:DeleteHash = $null
<# Displays the Windows Notification in the bottom-right of Windows #>
$script:WindowsNotification = $null
<# If there is an error uploading/deleting media, this will return the error-code value #>
$script:ErrorException = $null

<#~ Preset variables by user ~#>

<# Directory where ImgurUpload data is stored #>
$script:RootFolderDirectory = "$env:LOCALAPPDATA\Imgur"
<# Enable/Disable Debug Mode (Writes Outputs of all functions outputs)#>
$script:debug = $true
<# Shows the upload message in the bottom right when uploading a successful image #>
$script:DisplayWindowsNotifications = $true


<# Set local attributes within the file #>
Function Initialize-Imgur {

    [CmdletBinding()]
    param(
        [string]$FilePath,
        [string]$ClientID,
        [string]$Access_Token,
        [string]$DeleteHash
    )

    $script:FilePath = $FilePath
    $script:ClientID = $ClientID
    $script:Access_Token = $Access_Token
    $script:DeleteHash = $DeleteHash

    <# Display Debug Output #>
    If($script:debug) {
        $DebugContent = @{ FilePath=$script:FilePath; ClientID=$script:ClientID; AccessToken=$script:Access_Token; RefreshToken=$script:Refresh_Token; TokenType=$script:Token_Type }
        Write-ImgurDebugOutput -Function $MyInvocation.MyCommand -DebugContent $DebugContent
    }
}

Function Initialize-ImgurScripts {

    [CmdletBinding()] param([string]$ImgurScriptPath)

    <# If ImgurScriptPath is not specicfied when running Initialize-ImgurScripts -ImgurScriptPath "C:\Example\imgur-scripts.bin" ~ will look in root path for imgur script file#>
    If(($ImgurScriptPath -eq $null) -or ($ImgurScriptPath.Length -lt 1)) {
        $ImgurLocalScriptPath = (Get-ChildItem | Where-Object Name -eq "imgur-scripts.bin").VersionInfo.FileName
        If(($null -ne $ImgurLocalScriptPath) -and ($ImgurLocalScriptPath.Length -gt 1)) {
            $ImgurScriptPath = $ImgurLocalScriptPath
        }
    }

    If($ImgurScriptPath.Length -gt 1) {
        Expand-ImgurScripts -ImgurScriptPath $ImgurScriptPath
    } else {
        Write-Output "File not found: ""imgur-scripts.bin"" - File needs to be in the same directory as Imgur.psm1."
    }
}

<# Downloads latest imgur-scripts.bin file from online #>
Function Update-ImgurModule {

    $ProgressPreference = 'SilentlyContinue'
    $Hash = Invoke-WebRequest -Uri "https://archive.portal.ms/bin/imgur-scripts/hash.php" -UserAgent "ImgurPowerShell -Kai"

    $isValidHash = ($Hash -match '[A-Fa-f0-9]{64}')

    If(!($isValidHash)) {
        return Write-Output "Invalid SHA256 Hash."
    }

    Try {

        $ArchiveFileURL = ("https://archive.portal.ms/bin/imgur-scripts/" + $Hash)
        $OutFilePath = ($env:LOCALAPPDATA + "\imgur-scripts.bin")
    
        $ProgressPreference = 'SilentlyContinue'
        Invoke-WebRequest -Uri $ArchiveFileURL -OutFile $OutFilePath
    
        $OutFilePathExists = Test-Path -Path $OutFilePath
        If($OutFilePathExists) {
            $OutFileHash = (Get-FileHash -Path $OutFilePath).Hash
            # Security check - Compares FileHash to the file that was downloaded before executing the extraction process
            If($OutFileHash -eq $Hash) {
                $UpdateNeeded = (Compare-ImgurScriptsVersion -ImgurScriptPath $OutFilePath)
                If($UpdateNeeded) {
                    Initialize-ImgurScripts -ImgurScriptPath $OutFilePath
                    Write-Output "You have updated to the latest Imgur Module."
                } else {
                    Write-Output "You already have the latest Imgur Module."
                }
            } else {
                Write-Output ("Unable to update Imgur scripts as the FileHash do not match.")
            }
            Remove-Item -Path $OutFilePath -Force
        }
        } catch {
        Write-Output ("Error updating Imgur module: " + $_.Exception.Message)
    }
}

<#  Type:   Function-Void
#   Desc:   Requests the image to be uploaded to Imgur | Image is converted to Base64String
#   Usage:  New-ImgurUpload -FilePath "C:\.....Ssss.jpg"
#   Ref:    NONE #>
Function Expand-ImgurScripts {

    [CmdletBinding()] param([Parameter(Mandatory=$true)][string]$ImgurScriptPath)

    Add-Type -AssemblyName System.IO.Compression.FileSystem

    $ImgurScriptArchive = [System.IO.Compression.ZipFile]::Open($ImgurScriptPath, 'read')
    ForEach($ImgurScriptFile in $ImgurScriptArchive.Entries) {
        $ExtractPath = $ImgurScriptFile.FullName
        If($ExtractPath -like "*imgur-scripts/*") {
            $ExtractPath = $ExtractPath.Replace("imgur-scripts/", "")
        }
        $ExtractPath = ($env:LOCALAPPDATA + "/" + $ExtractPath)
        <# Checks if the ExtractPath has a backslash or forwardslash at the end of the string ~ SKIP if matches #>
        If(($ExtractPath -match '\$') -or ($ExtractPath -match '/$')) { continue }

        $DirectoryPath = Split-Path $ExtractPath

        If($debug) { Write-Output ("I Want to Extract: " + $ExtractPath); Write-Output ("Loaded directory: " + $DirectoryPath) }

        if(!(Test-Path $DirectoryPath)) {
            If($debug) { Write-Output ("Creating directory: " + $DirectoryPath) }
            New-Item -ItemType Directory -Path $DirectoryPath | Out-Null    
        }

        If($debug) { Write-Output ("Extract Data: " + $ExtractPath) }

        [System.IO.Compression.ZipFileExtensions]::ExtractToFile($ImgurScriptFile, $ExtractPath, $true)
    }
    $ImgurScriptArchive.Dispose()
}

<#  Type:   Function-Void
#   Desc:   Requests the image to be uploaded to Imgur | Image is converted to Base64String
#   Usage:  New-ImgurUpload -FilePath "C:\.....Ssss.jpg"
#   Ref:    NONE #>
Function Compare-ImgurScriptsVersion {

    [CmdletBinding()] param([Parameter(Mandatory=$true)][string]$ImgurScriptPath)

    <# Check if the FilePath "C:\Users\Kai\AppData\Local\Imgur" exists, if not - return $true #>
    $ImgurScriptPathExists = Test-Path -Path $script:RootFolderDirectory
    If(!($ImgurScriptPathExists)) {
        return $true
    } 

    Try {

    Add-Type -AssemblyName System.IO.Compression.FileSystem

    <# Load imgur.cfg json file from imgur-scripts.bin\imgur.cfg #>
    $ImgurScriptArchive = [System.IO.Compression.ZipFile]::OpenRead($ImgurScriptPath)
    $ImgurConfigFile = $ImgurScriptArchive.Entries | Where-Object Name -eq "imgur.cfg"
    $Stream = $ImgurConfigFile.Open()
    $StreamReader = New-Object IO.StreamReader($Stream)
    $NewImgurConfigContent = $StreamReader.ReadToEnd()
    $NewImgurScriptsBuild = ($NewImgurConfigContent | ConvertFrom-Json).build
    $StreamReader.Close()
    $Stream.Close()
    $ImgurScriptArchive.Dispose()

    <# Load imgur.cfg json file from C:\Users\Kai\AppData\Local\Imgur\imgur.cfg #>
    $StreamReaderCfg = New-Object IO.StreamReader($script:RootFolderDirectory + "\" + "imgur.cfg")
    $LocalImgurConfigContent = $StreamReaderCfg.ReadToEnd()
    $LocalImgurScriptBuild = ($LocalImgurConfigContent | ConvertFrom-Json).build
    $StreamReaderCfg.Close()

    } catch { 
        Write-Output ("Error comparing the ImgurScriptsVersion: " + $_.Exception.Message)
        return $false 
    }

    If($NewImgurScriptsBuild -gt $LocalImgurScriptBuild) {
        return $true
    }

    return $false
}

<#  Type:   Function-Void
#   Desc:   Requests the image to be uploaded to Imgur | Image is converted to Base64String
#   Usage:  New-ImgurUpload -FilePath "C:\.....Ssss.jpg"
#   Ref:    NONE #>
Function New-ImgurUpload {

    [CmdletBinding()] param([string]$FilePath) #Optional if FilePath was not set when using Initialize-Imgur

    If($FilePath.Length -lt 1) { $FilePath = $script:FilePath }

    <# Sets specific local script variables to $null (url & errorexception) #>
    Clear-ImgurAttributes

    $ConvertedImgToBase64 = [Convert]::ToBase64String((Get-Content $FilePath -Encoding byte))

    <# Try Catch to prevent continuing the script if the image fails to upload online #>
    try {
        $UploadRequest = Invoke-ImgurWebRequest -Base64Image $ConvertedImgToBase64 -Method "POST"
    } catch { 
        <# Output Error Messages #>
        $Exception = $_.Exception.Message
        Write-ImgurMessage -MessageType "CUSTOM" -CustomMessage "Your upload has failed - $Exception"
        Write-Output "For more information regarding these error codes/numbers, type the PowerShell command 'Get-ImgurResponseCodes'."
        <# Saves error message within the script - reference for other functions #>
        $script:ErrorException = $Exception
        <# Continue to output the standard debug info #>
        If($script:debug) {
            $DebugContent = @{ FilePath=$FilePath; ConvertedImgToBase64=$ConvertedImgToBase64;
            ConvertedJson=$ConvertedJson; URL=$script:URL; DeleteHash=$script:DeleteHash; Error=$Exception }
            Write-ImgurDebugOutput -Function $MyInvocation.MyCommand -DebugContent $DebugContent
        }
        <# Prevents the script below from running & retrieving more errors #>
        return $null
    }

    $ConvertedJson = ($UploadRequest.Content | ConvertFrom-Json)

    $script:URL = $ConvertedJson | Select-Object -ExpandProperty "data" | Select-Object -ExpandProperty "link"
    $script:DeleteHash = $ConvertedJson | Select-Object -ExpandProperty "data" | Select-Object -ExpandProperty "deletehash"

    If($null -ne $script:URL) {
        Write-ImgurMessage -MessageType "SUCCESS"
    }

    <# Display Debug Output #>
    If($script:debug) {
        $DebugContent = @{ FilePath=$FilePath; ConvertedImgToBase64=$ConvertedImgToBase64; ConvertedJson=$ConvertedJson; URL=$script:URL; DeleteHash=$script:DeleteHash }
        Write-ImgurDebugOutput -Function $MyInvocation.MyCommand -DebugContent $DebugContent
    }

}

<#  Type:   Function-Void
#   Desc:   Old Invoke-WebRequest Method - Available if .Net 4.5 is not installed
#   Usage:  Invoke-ImgurWebRequest -Base64Image "OASDKIQWDSAJ=...." -Method "POST" -DeleteHash "0123456789"
#   Ref:    {Remove-ImgurImage, New-ImgurUpload} #>
Function Invoke-ImgurWebRequest {

    [CmdletBinding()] 
    param(
        [string]$Base64Image,
        [Parameter(Mandatory=$true)][string]$Method,
        [string]$DeleteHash
    )

    $AuthorisationType = [int](Assert-ImgurIsLoggedIn)
    $Headers = Get-ImgurHeaders -OAuth2 $AuthorisationType

    If(($Method -eq "POST") -and ($Base64Image -ne $null)) { 
        $URI = "https://api.imgur.com/3/upload"
        $ExtraParams = @($Base64Image)
    } ElseIf(($Method -eq "DELETE") -and ($null -ne $DeleteHash)) {
        $URI = "https://api.imgur.com/3/image/"+$DeleteHash
    } Else {
        $URI = $null
    }

    If(($null -eq $URI) -or ($Method -eq $null) -or ($null -eq $Headers)) {
        return Write-Output "Invalid -Method or missing -DeleteHash/-Base64Image."
    }

    <# Display Debug Output #>
    If($script:debug) {
        $DebugContent = @{URI=$URI; Method=$Method; ExtraParams=$ExtraParams; Headers=$Headers}
        Write-ImgurDebugOutput -Function $MyInvocation.MyCommand -DebugContent $DebugContent
    }

    $ProgressPreference = 'SilentlyContinue'
    return Invoke-WebRequest -URI $URI -Method $Method -Body $ExtraParams -Headers $Headers
}

<#  Type:   Function-Void
#   Desc:   Requires .Net 4.5+ (2012 update) but is much better than Invoke-WebRequest/Invoke-RestRequest IMO - Works better with larger files & videos
#   Usage:  Invoke-ImgurHttpPostAsync -FilePath "C:\.....Developers.mp4"
#   Ref:    NONE #>
Function Invoke-ImgurHttpPostAsync {

    [CmdletBinding()] param([string]$FilePath)

    If($FilePath.Length -lt 1) { $FilePath = $script:FilePath }

    $ErrorActionPreference = 'Stop'

    #TODO ~

    $FieldName = 'image'
    $VideoExtensionType = @('.mp4', '.webm', '.mpeg')
    If($FilePath -contains $VideoExtensionType) {
        $FieldName = 'video'
    }
    #$FilePath = 'C:\Users\Kai\Downloads\Steve Ballmer Developers.mp4'
    #$FilePath = 'C:\Users\Kai\AppData\Local\ImgurUpload\it.png'
    #$url = 'https://api.imgur.com/3/upload'

    Try {
        Add-Type -AssemblyName 'System.Net.Http'
        $HttpClient = New-Object System.Net.Http.HttpClient
        #$client.DefaultRequestHeaders.Authorization = New-Object System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", "XXXXXXXXXXXXXXXXXXXXXXXXX")
        $Header = (Get-ImgurHeaders -OAuth2 ([int](Assert-ImgurIsLoggedIn)))
        $HttpClient.DefaultRequestHeaders.Add("Authorization", $Header.Values)
        $MultiFormDataContent = New-Object System.Net.Http.MultipartFormDataContent
        $FileStream = [System.IO.File]::OpenRead($FilePath)
        $FileName = [System.IO.Path]::GetFileName($FilePath)
        $FileContent = New-Object System.Net.Http.StreamContent($FileStream)
        $MultiFormDataContent.Add($FileContent, $FieldName, $FileName)
        If($script:debug) { $MultiFormDataContent.ReadAsStringAsync() | Out-File [Environment]::GetFolderPath("Desktop")+"\Async.txt" }
        $Result = $HttpClient.PostAsync('https://api.imgur.com/3/upload', $MultiFormDataContent).Result
        $Result.EnsureSuccessStatusCode()
        $Result.Content.ReadAsStringAsync().Result
    } Catch {
        Write-Error $_
        exit 1
    } Finally {
        If ($null -ne $HttpClient) { $HttpClient.Dispose() }
        If ($null -ne $MultiFormDataContent) { $MultiFormDataContent.Dispose() }
        If ($null -ne $FileStream) { $FileStream.Dispose() }
        If ($null -ne $FileContent) { $FileContent.Dispose() }
    }
}

<#  Type:   Function-Void
#   Desc:   Sign into Imgur by using the OAuth2 API
#   Usage:  Connect-ImgurOAuth2 -ClientId "0123456789"
#   Ref:    NONE #>
Function Connect-ImgurOAuth2 {

    [CmdletBinding()] param([string]$ClientID)

    $ClientID = Get-ImgurClientID

    If(!(Assert-ImgurReady -ClientID $ClientID)) { return $null }

    Add-Type -Assembly "Microsoft.VisualBasic"
    Add-Type -AssemblyName System.Windows.Forms

    $ApplicationConfig = @{Navigate2="https://api.imgur.com/oauth2/authorize?client_id=$ClientID&response_type=token&state=gettoken"; Height=800; Width=700; AddressBar=$False; Resizable=$False; MenuBar=$False; ToolBar=0; Visible=$True; Left=0; Top=0}

    $ScreenSize = [System.Windows.Forms.SystemInformation]::PrimaryMonitorSize
    $Position = @(($ScreenSize.Width/2-$ApplicationConfig.Width/2), ($ScreenSize.Height/2-$ApplicationConfig.Height/2))
    $ApplicationConfig.Left = $Position[0]; $ApplicationConfig.Top = $Position[1]

    $ImgurLogin = New-Object -ComObject InternetExplorer.Application -Property $ApplicationConfig

    $Process = Get-Process | Where-Object { $_.MainWindowHandle -eq $ImgurLogin.HWND }

    while(($null -ne $ImgurLogin.LocationURL) -and ($ImgurLogin.LocationURL -notlike "*access_token=*" -and $ImgurLogin.LocationURL -notlike "*access_denied*")) {
        If(($null -ne $Process) -and ($Process.Id -ne 0)) {
            [Microsoft.VisualBasic.Interaction]::AppActivate($Process.Id)
        }
        Start-Sleep -Milliseconds 600
    }

    <# Full URL Debug
    https://imgur.com/?state=gettoken#access_token=XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX&
    expires_in=315360000&token_type=bearer&refresh_token=XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX&
    account_username=XXXXXXX&account_id=XXXXXXXX
    #>

    $LastURL = $ImgurLogin.LocationURL

    If(($null -ne $Process) -and ($Process.Id -ne 0)) {
        $Process | Stop-Process -Force
    }

    If(($LastURL -notlike '*&*') -or ($LastURL -notlike '*#*')) {
        return Write-Output "Unable to gather Imgur Token Data."
    }

    $TokenDataArray = ($LastURL.split('&').split('#'))
    $TokenArray = @('access_token=', 'expires_in=', 'token_type=', 'refresh_token=', 'account_username=', 'account_id=')

    ForEach($Token in $TokenArray) {
        If($null -eq ($TokenDataArray -like "*$Token*")) { continue Write-Output "Not in array: "$Token }
        $EqualPosition = ($Token.IndexOf("=") + 1)
        switch($Token) {
            "access_token=" { $script:Access_Token = ($TokenDataArray -match $Token).Substring($EqualPosition) }
            "expires_in=" { $script:Token_Expire = ($TokenDataArray -match $Token).Substring($EqualPosition) }
            "token_type=" { $script:Token_Type = ($TokenDataArray -match $Token).Substring($EqualPosition) }
            "refresh_token=" { $script:Refresh_Token = ($TokenDataArray -match $Token).Substring($EqualPosition) }
            "account_username=" { $script:Account_Username = ($TokenDataArray -match $Token).Substring($EqualPosition) }
            "account_id=" { $script:Account_ID = ($TokenDataArray -match $Token).Substring($EqualPosition) }
        }
    }

    <# Display Debug Output #>
    If($script:debug) {
        $DebugContent = @{AccessToken=$script:Access_Token; RefreshToken=$script:Refresh_Token; AccountUsername=$script:Account_Username;
        AccountID=$script:Account_ID; TokenType=$script:Token_Type; TokenExpire=$script:Token_Expire; TokenDataArray=$TokenDataArray;
        TokenArray=$TokenArray; LastURL=$LastURL; ClientID=$ClientID}
        Write-ImgurDebugOutput -Function $MyInvocation.MyCommand -DebugContent $DebugContent
    }
}

<#  Type:   Function-Void
#   Desc:   Simple Baloon Notification (NotifyIcon) without using .NET DLL
#   Usage:  New-ImgurNotification -Text "Example Message" -RegisterClickEventHandler $true -ErrorIcon $false
#   Ref:    Write-ImgurMessage #>
Function New-ImgurNotification {

    [CmdletBinding()] param([Parameter(Mandatory=$true)][string]$Text,[Parameter(Mandatory=$true)][bool]$RegisterClickEventHandler, [bool]$ErrorIcon)

    <# Does not execute the script below, due to the user disabling the Windows Notification #>
    If(!($script:DisplayWindowsNotifications)) { return $null }

    <# Clear event handlers/jobs - Handling only 1 Balloon Notification ~ Multiple are annoying atm #>
    $EventsToRemove = @('BalloonTipClicked', 'BalloonTipClosed')
    ForEach ($EventToRemove in $EventsToRemove) {
        Remove-Event -SourceIdentifier $EventToRemove -ErrorAction SilentlyContinue
        Unregister-Event -SourceIdentifier $EventToRemove -ErrorAction SilentlyContinue
        Remove-Job -Name $EventToRemove -ErrorAction SilentlyContinue
    }
    If($null -ne $script:WindowsNotification) { $script:WindowsNotification.Dispose() }

    Add-Type -AssemblyName System.Windows.Forms

    <# Create script instance object of the WindowsNotification #>
    $script:WindowsNotification = New-Object System.Windows.Forms.NotifyIcon

    <# Displays the Error or Info Icon on the pop-up message #>
    $TipIcon = [System.Windows.Forms.ToolTipIcon]::Info
    If($ErrorIcon) { $TipIcon = [System.Windows.Forms.ToolTipIcon]::Error }

    <# Configure the data that is displayed, when the notification is shown #>
    $NotifyIcon = $script:WindowsNotification
    $NotifyIcon.Icon = [System.Drawing.Icon]::ExtractAssociatedIcon((Get-Process -id $pid).Path) 
    $NotifyIcon.BalloonTipIcon = $TipIcon
    $NotifyIcon.BalloonTipText = $Text
    $NotifyIcon.BalloonTipTitle = "Imgur (PowerShell)"
    $NotifyIcon.Visible = $true 
    
    <# Create Click&Close Event when Clicking Main Notification #>
    If($RegisterClickEventHandler) {
        Register-ObjectEvent -InputObject $NotifyIcon -EventName BalloonTipClicked -Source "BalloonTipClicked" -Action { (Get-ImgurNotificationAction -Action "NAVIGATE_TO_URL") }
        Register-ObjectEvent -InputObject $NotifyIcon -EventName BalloonTipClosed -Source "BalloonTipClosed" -Action { (Get-ImgurNotificationAction -Action "DISPOSE") }
    }

    <# Display the Notification for 5 seconds (Default) #>
    $NotifyIcon.ShowBalloonTip(5000)
}

<#  Type:   Function-Void
#   Desc:   Private function for triggering the Action which is used for the Windows Notification
#   Usage:  Get-ImgurNotificationAction -Action "NAVIGATE_TO_URL"
#   Ref:    New-ImgurNotification #>
Function Get-ImgurNotificationAction {

    [CmdletBinding()] param([Parameter(Mandatory=$true)][string]$Action)

    $NotificationAction = [scriptblock]::Create($(switch($Action) {
        <# Opens the default web-browser & navigates to the last image uploaded #>
        "NAVIGATE_TO_URL" {

            If($null -eq $script:URL) { return $null }

            <# Action #>
            $NotificationProcess = Start-Process $script:URL -PassThru
            Start-Sleep -Seconds 2
            [Microsoft.VisualBasic.Interaction]::AppActivate($NotificationProcess.Id)

            <# Dispose & Remove event handlers #>
            $Events = @('BalloonTipClicked', 'BalloonTipClosed')
            ForEach($Event in $Events) {
                Unregister-Event -Source $Event -ErrorAction SilentlyContinue
                Remove-Job -Name $Event -ErrorAction SilentlyContinue
            }
            <# Close the Notification from the Mini-Taskbar #>
            If($null -ne $script:WindowsNotification) { $script:WindowsNotification.Visible = $false; $script:WindowsNotification.Dispose() }
        }
        <# (Overwrites) Copies the URL to the clipboard - ready to paste instantly #>
        "COPY_URL_TO_CLIPBOARD" {
            Set-Clipboard $script:URL
        }

        <# Close the Notification from the Mini-Taskbar & Removes event handlers #>
        "DISPOSE" {
            $Events = @('BalloonTipClicked', 'BalloonTipClosed')
            ForEach($Event in $Events) {
                Unregister-Event -Source $Event -ErrorAction SilentlyContinue
                Remove-Job -Name $Event -ErrorAction SilentlyContinue
           }
           If($null -ne $script:WindowsNotification) { $script:WindowsNotification.Dispose() }
        }
    }))

    return $NotificationAction
}

<#  Type:   Function-Void
#   Desc:   Deletes an image from Imgur that is uploaded
#   Usage:  Remove-ImgurImage -DeleteHash "0123456789"
#   Ref:    NONE #>
Function Remove-ImgurImage {
    [CmdletBinding()] param([string]$DeleteHash) #Optional
    If($null -eq $DeleteHash) { $DeleteHash = $script:DeleteHash }
    Invoke-ImgurWebRequest -Method "DELETE" -DeleteHash $DeleteHash
}


<#  Type:   Function-Void
#   Desc:   This function is used to output debug data (to the PowerShell window) - useful for finding errors
#   Usage:  Write-ImgurDebugOutput -Function "Get-ExampleFunction" -DebugContent "PSObject{Test=Test, Test2=Test2}"
#   Ref:    {Initialize-Imgur, New-ImgurUpload, Invoke-ImgurWebRequest, Connect-ImgurOAuth2} #>
Function Write-ImgurDebugOutput {
    [CmdletBinding()] param([Parameter(Mandatory=$true)][string]$Function, [Parameter(Mandatory=$true)][psobject]$DebugContent)

    $BlacklistedFunctions = @() #Example Write-ImgurDebugOutput
    If($BlacklistedFunctions -notcontains $Function) {
        Write-Output "[DEBUG-FUNCTION] $Function"
        Write-Output ($DebugContent | Format-List)
    }
}

<#  Type:   Function-Void
#   Desc:   Outputs the text within the PowerShell window & sends a Balloon Notification
#   Usage:  Write-ImgurMessage -MessageType "CUSTOM" -CustomMessage "EXAMPLE"
#   Ref:    {New-ImgurUpload} #>
Function Write-ImgurMessage {
    [CmdletBinding()] param([Parameter(Mandatory=$true)][string]$MessageType, [string]$CustomMessage)

    switch($MessageType) {
        "SUCCESS" { $message = "Your upload was successfull ~ $script:URL"; Write-Output $message; New-ImgurNotification -Text $message -RegisterClickEventHandler $true -ErrorIcon $false }
        "FAILED" { $message = "Your upload has failed."; Write-Output $message; New-ImgurNotification -Text $message -RegisterClickEventHandler $false -ErrorIcon $true }
        "CUSTOM" { $message = $CustomMessage; Write-Output $message; New-ImgurNotification -Text $message -RegisterClickEventHandler $false -ErrorIcon $true }
    }
}

<# [Return Boolean Function] ImgurIsLoggedIn
(?) What does this function do
(!) Returns $true or $false - If the Access Token is not $null ($script:Access_Token)

(?) How does someone get an Access Token & Populate the variable ($script:Access_Token)
(!) Either use Connect-ImgurOAuth2 & sign-in, or set the Access Token manually within Initialize-Imgur
#>
Function Assert-ImgurIsLoggedIn {
    If($null -ne $script:Access_Token) { return $true } return $false
}

<# Public function to return ClientID from the script session #>
Function Get-ImgurClientID {
    [CmdletBinding()] param([string]$ClientID)
    If($ClientID.Length -lt 1) { $ClientID = $script:ClientID }
    return $ClientID
}

<#  Type:   Function-Boolean
#   Desc:   Checks if the PowerShell Process is being ran with Adminstrative Privilege
#   Usage:  Assert-IsAdministrator
#   Ref:    NONE #>
Function Assert-IsAdministrator {
    $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    If($isAdmin) { return $true } return $false
}

<#  Type:   Function-Boolean
#   Desc:   Returns a message if the ClientID does not exist within the script
#   Usage:  Assert-ImgurReady -ClientId "0123456789"
#   Ref:    {Connect-ImgurOAuth2} #>
Function Assert-ImgurReady {
    [CmdletBinding()] param([string]$ClientID)
    $ClientID = Get-ImgurClientID -ClientID $ClientID
    If(($null -eq $ClientID) -or ($ClientID.Length -lt 1)) {
        Write-Output "Your ClientID can't be empty.`nYou can create a new Imgur ClientID by typing the command < Register-ClientID >."
        return $false
    }
    return $true
}

<#  Type:   Function-GetString
#   Desc:   Return DeleteHash from the script session
#   Usage:  Get-ImgurDeleteHash
#   Ref:    NONE #>
Function Get-ImgurDeleteHash {
    return $script:DeleteHash
}

<#  Type:   Function-Get
#   Desc:   Required for Invoke-ImgurWebRequest ~ Header field
#   Usage:  Get-ImgurHeaders -OAuth2 $false
#   Ref:    {Invoke-ImgurWebRequest, Invoke-ImgurHttpPostAsync} #>
Function Get-ImgurHeaders {
    [CmdletBinding()] param([boolean]$OAuth2)
    If($OAuth2) {
        return @{"Authorization" = "Bearer $script:Access_Token"}
    }
    return @{"Authorization" = "Client-ID $script:ClientID"}
}

<#  Type:   Function-Get
#   Desc:   Outputs the StatusCode Error List from Imgur - Ref: https://api.imgur.com/errorhandling
#   Usage:  Get-ImgurResponseCodes
#   Ref:    {New-ImgurUpload} #>
Function Get-ImgurResponseCodes {
    $ResponseCodes = @([PSCustomObject]@{ StatusCode="200"; Description="The request has succeeded and there were no errors. Congrats!"},
    [PSCustomObject]@{ StatusCode="400"; Description="This error indicates that a required parameter is missing or a parameter has a value that is out of bounds or otherwise incorrect. This status code is also returned when image uploads fail due to images that are corrupt or do not meet the format requirements."},
    [PSCustomObject]@{ StatusCode="401"; Description="The request requires user authentication. Either you didn't send send OAuth credentials, or the ones you sent were invalid."},
    [PSCustomObject]@{ StatusCode="403"; Description="Forbidden. You don't have access to this action. If you're getting this error, check that you haven't run out of API credits or make sure you're sending the OAuth headers correctly and have valid tokens/secrets."},
    [PSCustomObject]@{ StatusCode="404"; Description="Resource does not exist. This indicates you have requested a resource that does not exist. For example, requesting an image that doesn't exist."},
    [PSCustomObject]@{ StatusCode="429"; Description="Rate limiting. This indicates you have hit either the rate limiting on the application or on the user's IP address."},
    [PSCustomObject]@{ StatusCode="500"; Description="Unexpected internal error. What it says. We'll strive NOT to return these but your app should be prepared to see it. It basically means that something is broken with the Imgur service."})
    <# Prints response codes above to the PowerShell command-line #>
    Write-Output $ResponseCodes | Format-List
}

<#  Type:   Function-Void
#   Desc:   Clears the $script:URL & $script:ErrorException attributes
#   Usage:  Clear-ImgurAttributes
#   Ref:    {New-ImgurUpload} #>
Function Clear-ImgurAttributes {
    $script:URL = $null
    $script:ErrorException = $null
}

<#  Type:   Function-Void
#   Desc:   Opens the registering page to create the OAuth ClientID
#   Usage:  Register-ClientID
#   Ref:    {Assert-ImgurReady} #>
Function Register-ClientID {
    Start-Process "https://api.imgur.com/oauth2/addclient"
}
