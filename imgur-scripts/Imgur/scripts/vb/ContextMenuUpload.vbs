Set objArgs = WScript.Arguments ' Create object.
Path=objArgs(0)

Set oShell = CreateObject("WScript.Shell")
strLocalAppData = oShell.ExpandEnvironmentStrings("%LOCALAPPDATA%")

MsgBox "powershell.exe -nologo -command """+strLocalAppData+"\Imgur\scripts\ps\ContextMenuUpload.ps1"" " & Path

command = "powershell.exe -nologo -command """+strLocalAppData+"\Imgur\scripts\ps\ContextMenuUpload.ps1"" " & Path
 set shell = CreateObject("WScript.Shell")
 shell.Run command,0
