$AppLocation = "$env:LOCALAPPDATA\Imgur\"

<# Debug Text File for troubleshooting purposes #>
Start-Transcript

$FileName = "ContextMenuUploadTestDoc.txt"
$FileInformation = $args -join " "
$Data = @($FileInformation.Length, $FileInformation, $FileInformation[0])
$Data | Out-File $AppLocation+$FileName

<# Remove & Import Imgur Module #>
Remove-Module Imgur
Import-Module $AppLocation"\scripts\Imgur.psm1"

<# Upload Image to Imgur #>
If($null -ne $FileInformation) {
    Initialize-Imgur -ClientID "XXXXXXXXXX" -FilePath $FileInformation
    New-ImgurUpload
}

Stop-Transcript
