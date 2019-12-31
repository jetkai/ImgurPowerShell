<# CLASS #>


<# [Function] ImgurRegistry 
(!!!) FUNCTION REQUIRES WINDOWS ADMINISTRATOR RIGHTS
(?) What does this function do
(!) Calls the two functions New-ImgurContextMenu & New-ImgurFileType

(?) What uses this function
(!) TODO
#>
Function Initialize-ImgurRegistry {

    [CmdletBinding()] param([Parameter(Mandatory=$true)][bool]$UpdateRegistry)

    If(!(Assert-IsAdministrator)) {
        return Write-Output "Sorry, you need to run this PowerShell instance as Administrator to use this command."
    }

    If($UpdateRegistry) {
        New-ImgurContextMenu -UpdateRegistry $true
        New-ImgurFileType -UpdateRegistry $true
    }
}


<# [Function] ImgurContextMenu
(!!!) FUNCTION REQUIRES WINDOWS ADMINISTRATOR RIGHTS

(?) What does this function do
(!) Creates the right-click option "Upload to Imgur", when right-clicking file extensions - '.jpg', '.png', '.jpeg', '.mp4', '.webm', '.mpeg', 'mpg', 'gif'
(!EXTRA) Upon clicking the option "Upload to Imgur", this initializes a PowerShell script which will call "New-ImgurUpload" & upload the image/video to Imgur

(?) What uses this function
(!) @New-ImgurBuildRegistry
#>
Function New-ImgurContextMenu {

    [CmdletBinding()] param([Parameter(Mandatory=$true)][bool]$UpdateRegistry)

    <# Return unless requested by $UpdateRegistry boolean #>
    If(($UpdateRegistry)) { return $null }

    If(!(Assert-IsAdministrator)) {
        return Write-Output "Sorry, you need to run this PowerShell instance as Administrator to use this command."
    }

    New-PSDrive -Name HKCR -PSProvider Registry -Root HKEY_CLASSES_ROOT

    $RootFileAssociationsLocation = "HKCR:\SystemFileAssociations"
    $Extensions = @('.jpg', '.png', '.jpeg', '.mp4', '.webm', '.mpeg', 'mpg', 'gif')

    ForEach($Extension in $Extensions) {
        
        #Checks Exists: Computer\HKEY_CLASSES_ROOT\SystemFileAssociations\.* -> Terminate script if extension does not exist
        If(($Extension.Length -lt 1) -or !(Test-Path -Path $RootFileAssociationsLocation'\'$Extension)) { continue }

        #Checks Exists: Computer\HKEY_CLASSES_ROOT\SystemFileAssociations\.*\Shell
        $Path0Exists = Test-Path -Path $RootFileAssociationsLocation'\'$Extension'\Shell'

        If(!($Path0Exists)) {
            #Create Key: Computer\HKEY_CLASSES_ROOT\SystemFileAssociations\.*\Shell
            New-Item $RootFileAssociationsLocation'\'$Extension'\Shell' -Force
        }

        #Checks Exists: Computer\HKEY_CLASSES_ROOT\SystemFileAssociations\.*\Shell\Upload to Imgur
        $Path1Exists = Test-Path -Path $RootFileAssociationsLocation'\'$Extension'\Shell\Upload to Imgur'

        If(!($Path1Exists)) {
            #Create Key: Computer\HKEY_CLASSES_ROOT\SystemFileAssociations\.*\Shell\Upload to Imgur
            $Path1Item = New-Item $RootFileAssociationsLocation'\'$Extension'\Shell\Upload to Imgur' -Force
            #Create Default String: Computer\HKEY_CLASSES_ROOT\SystemFileAssociations\.*\Shell\Upload to Imgur -> (Default) ~ "Upload to Imgur"
            $Path1Item | New-ItemProperty -Name '(Default)' -PropertyType String -Value "Upload to Imgur" -Force
            #Create Icon String: Computer\HKEY_CLASSES_ROOT\SystemFileAssociations\.*\Shell\Upload to Imgur -> Icon ~ "%localappdata%\Imgur\assets\imgur.ico"
            $Path1Item | New-ItemProperty -Name 'Icon' -PropertyType String -Value "%localappdata%\Imgur\assets\imgur.ico" -Force
        }

        #Checks Exists: Computer\HKEY_CLASSES_ROOT\SystemFileAssociations\.*\Shell\Upload to Imgur\command
        $Path2Exists = Test-Path -Path $RootFileAssociationsLocation'\'$Extension'\Shell\Upload to Imgur\command'

        If(!($Path2Exists)) {
            #Create Key: Computer\HKEY_CLASSES_ROOT\SystemFileAssociations\.*\Shell\Upload to Imgur\command
            $Path2Item = New-Item $RootFileAssociationsLocation'\'$Extension'\Shell\Upload to Imgur\command' -Force
            #Create ExpandString: Computer\HKEY_CLASSES_ROOT\SystemFileAssociations\.*\Shell\Upload to Imgur\command -> (Default) ~ ""%windir%\system32\wscript.exe" "%localappdata%\Imgur\scripts\ContextMenuUpload.vbs" "%1""
            $Path2Item | New-ItemProperty -Name '(Default)' -PropertyType ExpandString -Value '"%windir%\system32\wscript.exe" "%localappdata%\Imgur\scripts\vb\ContextMenuUpload.vbs" "%1"' -Force
        }
    }
}

<# [Function] ImgurFileType
(!!!) FUNCTION REQUIRES WINDOWS ADMINISTRATOR RIGHTS

(?) What does this function do
(!) Creates the .imgur file extention, using the Windows Registry
(!) Displays the imgur logo for the .imgur file extension
(!EXTRA) When clicking the .imgur file extension, it will navigate you straight to the image on Imgur (Website)
(!EXTRA) .imgur file extension has an additional right-click context menu item - "Delete from Imgur"

(?) What uses this function
(!) @New-ImgurBuildRegistry
#>
Function New-ImgurFileType {

    [CmdletBinding()] param([Parameter(Mandatory=$true)][bool]$UpdateRegistry)

    <# Return unless requested by $UpdateRegistry boolean #>
    If(($UpdateRegistry)) { return $null }

    If(!(Assert-IsAdministrator)) {
        return Write-Output "Sorry, you need to run this PowerShell instance as Administrator to use this command."
    }

    New-PSDrive -Name HKCR -PSProvider Registry -Root HKEY_CLASSES_ROOT
    #Path Example: Computer\HKEY_CLASSES_ROOT\imgurfile\Shell\Open\Command

    $RootImgurFileLocation = "HKCR:\imgurfile"
    $ImgurFilePathExists = Test-Path -Path $RootFileAssociationsLocation #~ Check Exists: Computer\HKEY_CLASSES_ROOT\imgurfile

    If(!($ImgurFilePathExists)) {
        #Create Key: Computer\HKEY_CLASSES_ROOT\imgurfile
        $ImgurPath0Item = New-Item $RootImgurFileLocation
        #Create Key: Computer\HKEY_CLASSES_ROOT\imgurfile\Shell
        $ImgurPath0Item | New-Item $RootImgurFileLocation'\Shell' -Force | New-Item $RootImgurFileLocation'\Shell\Open' -Force | New-Item $RootImgurFileLocation'\Shell\Open\Command' -Force
        #Create Key: Computer\HKEY_CLASSES_ROOT\imgurfile\DefaultIcon
        $ImgurPath0Item | New-Item $RootImgurFileLocation'\DefaultIcon' -Force

        $CommandPathExists = Test-Path -Path $RootFileAssociationsLocation'\Shell\Open\Command'
        If($CommandPathExists) {
            New-ItemProperty -Path $RootFileAssociationsLocation'\Shell\Open\Command' -Name '(Default)' -PropertyType ExpandString 
            -Value '"%windir%\system32\wscript.exe" "%localappdata%\Imgur\scripts\vb\ContextMenuUpload.vbs" "%1"' -Force
        }

        $DefaultIconPathExists = Test-Path -Path $RootFileAssociationsLocation'\DefaultIcon'
        If($DefaultIconPathExists) {
            New-ItemProperty -Path $RootFileAssociationsLocation'\DefaultIcon' -Name '(Default)' -PropertyType ExpandString
            -Value "%localappdata%\Imgur\assets\imgur.ico" -Force
        }
    }

    <# Refresh Icons for WindowsOS ~ ie4uinit.exe is a default utility application included with WindowsOS #>
    $isAboveWindows8 = [Environment]::OSVersion.Version -ge (New-Object 'Version' 8,1)

    If($isAboveWindows8) {
        Start-Process "C:\Windows\System32\ie4uinit.exe" -ArgumentList "-show"
    } else {
        Start-Process "C:\Windows\System32\ie4uinit.exe" -ArgumentList "-ClearIconCache"
    }
}

Function Assert-IsAdministrator {
    $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    If($isAdmin) { 
        return $true 
    } 
    return $false
}