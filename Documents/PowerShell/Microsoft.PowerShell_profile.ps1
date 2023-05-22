using namespace System.Management.Automation
using namespace System.Management.Automation.Language

Set-PSReadLineOption -PredictionSource History
Set-PSReadLineOption -PredictionViewStyle ListView
Set-PSReadLineOption -EditMode Windows
Set-PSReadlineOption -BellStyle None

Import-Module -Name posh-git

if ((-not [string]::IsNullOrEmpty($env:WT_SESSION)) -or ($env:TERM_PROGRAM -eq 'vscode')) {
    # oh-my-posh --init --shell pwsh --config C:\Users\spletzr\AppData\Local\Programs\oh-my-posh\themes\ohmyposhv3-v2.json | Invoke-Expression
    oh-my-posh --init --shell pwsh --config $env:USERPROFILE/.oh-my-posh/themes/mytheme.json | Invoke-Expression
    Import-Module -Name Terminal-Icons
}

Register-ArgumentCompleter -Native -CommandName winget -ScriptBlock {
    param (
        $wordToComplete,
        $commandAst,
        $cursorPosition
    )

    [Console]::InputEncoding = [Console]::OutputEncoding = $OutputEncoding = [System.Text.Utf8Encoding]::new()
    $Local:word = $wordToComplete.Replace('"', '""')
    $Local:ast = $commandAst.ToString().Replace('"', '""')
    winget complete --word="$Local:word" --commandline "$Local:ast" --position $cursorPosition | ForEach-Object {
        [System.Management.Automation.CompletionResult]::new($_, $_, 'ParameterValue', $_)
    }
}

# PowerShell parameter completion shim for the dotnet CLI
Register-ArgumentCompleter -Native -CommandName dotnet -ScriptBlock {
    param (
        $commandName,
        $wordToComplete,
        $cursorPosition
    )

    dotnet complete --position $cursorPosition "$wordToComplete" | ForEach-Object -Process {
        [System.Management.Automation.CompletionResult]::new($_, $_, 'ParameterValue', $_)
    }
}

if ((Get-Location).Path -eq 'C:\Windows\System32') {
    Set-Location -Path $env:USERPROFILE
}

if ([string]::IsNullOrEmpty($env:USERNAME)) {
    $env:USERNAME = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name.Split('\')[1]
}

function Open-GitRemoteUrl {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$false)]
        [string]
        $RemoteName = 'origin'
    )

    begin {}

    process {
        Start-Process -FilePath (git remote get-url $RemoteName)
    }

    end {}
}

New-Alias -Name openremote -Value Open-GitRemoteUrl

function Sync-GitOriginRemoteFromUpstream {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [Alias('b')]
        [string]
        $Branch,

        [Parameter(Mandatory = $false)]
        [Alias('f')]
        [switch]
        $Force
    )

    begin {}

    process {
        $b = git branch --show-current
        $trunk = $null
        if ($b -notmatch '(main|master)') {
            if (git branch | Select-String -Pattern main) {
                $trunk = 'main'
                git checkout $trunk
            } else {
                $trunk = 'master'
                git checkout $trunk
            }

            if ($Force.IsPresent) {
                git branch -D $b
            }
        }

        if ($null -eq $trunk) {
            if ($null -eq (git branch | Select-String -Pattern 'main')) {
                $trunk = 'master'
            } else {
                $trunk = 'main'
            }
        }

        git pull upstream $trunk
        git push
        git remote prune origin
        if (-not [string]::IsNullOrEmpty($Branch)) {
            git branch -D $branch
        }
    }

    end {}
}

New-Alias -Name syncremote -Value Sync-GitOriginRemoteFromUpstream

function Get-TypeAccelerators {
    [CmdletBinding()]
    param ()

    begin {}

    process {
        [psobject].Assembly.GetType("System.Management.Automation.TypeAccelerators")::get
    }

    end {}
}

# Chocolatey profile
$ChocolateyProfile = "$env:ChocolateyInstall\helpers\chocolateyProfile.psm1"
if (Test-Path -Path $ChocolateyProfile) {
    Import-Module -Name "$ChocolateyProfile"
}

function Enter-ElevatedPSSession {
#requires -Version 2.0

<#
.SYNOPSIS
    Enters a new elevated powershell process.
.DESCRIPTION
    Enters a new elevated powershell process. You can optionally close your existing session.
.PARAMETER CloseExisting
    If specified, the existing powershell session will be closed.
.NOTES
    UAC will prompt you if it is enabled.
    Starts new administrative session.
    Will do nothing if you are already running elevated.
.EXAMPLE
    # Running as normal user
    C:\Users\Joe> Enter-ElevatedPSSession
    # Starts new PowerShell process / session as administrator, keeping current session open.
.EXAMPLE
    # Running as normal user
    C:\Users\Joe> Enter-ElevatedPSSession -CloseExisting
    # Starts new PowerShell process / session as administrator, exiting the current session.
.EXAMPLE
    # Running already as administrator
    C:\Windows\System32> Enter-ElevatedPSSession
    Already running as administrator.
    # Message is written to host.
#>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$false,
                   Position=0)]
        [Alias('c')]
        [switch]
        $CloseExisting
    )

    begin {
        $runningProcess = 'powershell'
        if ((Get-Process -Id $pid).Name -eq 'powershell_ise') {
            $runningProcess = 'powershell_ise'
        }

        $Identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        $Principal = New-Object System.Security.Principal.WindowsPrincipal($Identity)
        $isAdmin = $Principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
    }

    process {
        if ($isAdmin) {
            Write-Host -Object "Already running as administrator."
            return
        }

        if ($CloseExisting.IsPresent) {
            Start-Process -FilePath $runningProcess -Verb RunAs -WorkingDirectory $pwd.Path
            exit
        } else {
            Start-Process -FilePath $runningProcess -Verb RunAs -WorkingDirectory $pwd.Path
        }
    }

    end {}
}

New-Alias -Name su -Value Enter-ElevatedPSSession

function Wait-Screen {
    [CmdletBinding()]
    param ()

    begin {}

    process {
        $wShell = New-Object -Com Wscript.Shell
        while (1) {
            $wShell.SendKeys("{SCROLLLOCK}")
            Start-Sleep -Seconds 60
        }
    }

    end {}
}

function MouseWiggle {
    Add-Type -Assembly System.Windows.Forms
    while($true) {
        Start-Sleep -Seconds 1
        [Windows.Forms.Cursor]::Position = New-Object Drawing.Point (random 1000),(random 1000)
    }
}
