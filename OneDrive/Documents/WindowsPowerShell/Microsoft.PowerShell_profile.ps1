$originalProfilePath = (
    Resolve-Path -Path "$env:USERPROFILE/Documents/PowerShell/Microsoft.PowerShell_profile.ps1"
).Path
if (-not ($PSScriptRoot -eq $originalProfilePath)) {
    . $originalProfilePath
}
