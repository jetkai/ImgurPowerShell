<# [Function] ImgurHistoryFile

(?) What does this function do
(!) Creates a .imgur file that follows the format:

{
    "URL":  "https://i.imgur.com/XXXXXXXX.png",
    "ErrorException":  null,
    "FileName":  "yt.png",
    "AccountID":  null,
    "AccountUsername":  null,
    "Time":  "00:00:15",
    "Date":  "10-12-2019",
    "DeleteHash":  "XXXXXXXXXX",
    "FilePath":  "C:\\Users\\Kai\\Desktop\\Office 365 Signature Creator\\compact-logo\\XXXXXX.png",
    "ImgurFileName":  "XXXXXXX.png",
    "Authorization":  [
                          "Bearer XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
                      ]
}

(?) Where is the .imgur file saved
(!) Within your local app data -> ImgurUpload path (C:\Users\Kai\AppData\Local\ImgurUpload\uploads\10-12-2019)


(?) What uses this function
(!) TODO
#>

Function Write-ImgurHistoryFile {

    [CmdletBinding()] param(
        [Parameter(Mandatory=$true)][string]$FilePath,
        [Parameter(Mandatory=$true)][psobject]$ImgurData)

    $FileName = Split-Path $FilePath -Leaf
    $ImgurFileName = Split-Path $script:URL -Leaf
    $CurrentDate = Get-Date -Format dd-MM-yyyy
    $CurrentTime = Get-Date -Format HH:mm:ss
    $HistoryPath = "$env:LOCALAPPDATA\Imgur\uploads\" + $CurrentDate
    
    <# TODO FIX THESE#>
    # $AuthorizationType = (Get-ImgurHeaders -OAuth2 ([int](Assert-ImgurIsLoggedIn))).Values
    # $ErrorException = $script:ErrorException

    <# Creates Folder Path (with date) - Example: C:\Users\Kai\AppData\Local\Imgur\uploads\10-12-2019 #>
    If(!(Test-Path $HistoryPath)) { 
        New-Item -ItemType Directory -Force -Path $HistoryPath 
    }

    $ImgurData += @{ Date=$CurrentDate; Time=$CurrentTime; FilePath=$FilePath; FileName=$FileName; ImgurFileName=$ImgurFileName }
    
    # $ImgurData = @{ Date=$CurrentDate; Time=$CurrentTime; FilePath=$script:FilePath; FileName=$FileName; ImgurFileName=$ImgurFileName; 
    #    DeleteHash=$script:DeleteHash; URL=$script:URL; AccountUsername=$script:Account_Username; AccountID=$script:Account_ID; Authorization=$AuthorizationType;
    #    ErrorException=$ErrorException }

    $ExportFilePath = $HistoryPath + "\" + $FileName + " - " + $ImgurFileName + ".imgur"

    $ImgurData | ConvertTo-Json | Out-File -FilePath $ExportFilePath

}