using namespace System.Management.Automation
using namespace System.Management.Automation.Language

if ($host.Name -eq 'ConsoleHost') {
    Remove-Module -Name PSReadLine -Force
    Import-Module -Name PSReadline -RequiredVersion 2.2.0 -Force
}

if ((-not [string]::IsNullOrEmpty($env:WT_SESSION)) -or ($env:TERM_PROGRAM -eq 'vscode')) {
    oh-my-posh --init --shell pwsh --config C:\Users\spletzr\AppData\Local\Programs\oh-my-posh\themes\ohmyposhv3-v2.json | Invoke-Expression
    Import-Module -Name posh-git
    Import-Module -Name Terminal-Icons
} else {
    Import-Module -Name posh-git
    $GitPromptSettings.DefaultPromptAbbreviateHomeDirectory = $true
    $GitPromptSettings.DefaultPromptPrefix = @'
$($env:USERNAME + '@' + $env:COMPUTERNAME + ' : ')
'@
    $GitPromptSettings.DefaultPromptSuffix = @'
$("`n" + ('>' * ($nestedPromptLevel + 1)) + ' ')
'@
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

Set-PSReadLineOption -PredictionSource History
Set-PSReadLineOption -PredictionViewStyle ListView
Set-PSReadLineOption -EditMode Windows

if ((Get-Location).Path -eq 'C:\Windows\System32') {
    Set-Location -Path $env:USERPROFILE
}

if ((-not $IsMacOS) -and (-not $IsLinux)) {
    if ([string]::IsNullOrEmpty($env:USERNAME)) {
        $env:USERNAME = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name.Split('\')[1]
    }
}

if ($IsMacOS -or $IsLinux) {
    $env:USERNAME = $env:USER
}

$env:VAULT_ADDR = 'https://vault.aws.autodesk.com'
$env:VAULT_FORMAT = 'json'
$env:PACKER_LOG = 1
$env:PACKER_LOG_PATH = 'packerlog.txt'
$env:VAULTPRDPACKERCREDSPATH = 'eis/directoryservices-prd/aws/directorysvcs-prd/creds/packer-inlinepolicy-role'
$env:CLOUDPCCOMPUTERNAME = 'CPSCLW10-0489.ads.autodesk.com'
$env:WORKSTATIONCOMPUTERNAME = 'ADSKR911G96J.ads.autodesk.com'
$env:DEFAULTDC = 'AWSUSWE2DC04.ads.autodesk.com'
$env:DEFAULTDEVDC = 'ADSDUSW2A-064.adsdev.autodesk.com'
$env:DEFAULTSTGDC = 'ARSDC3.adsstg.autodesk.com'
$env:ADPRDCS = @'
EW1PRIFSADC01.adpr.adskengineer.net
EW1PRIFSADC02.adpr.adskengineer.net
UE1PRIFSADC01.adpr.adskengineer.net
UE1PRIFSADC02.adpr.adskengineer.net
UW1PRIFSADC01.adpr.adskengineer.net
UW1PRIFSADC02.adpr.adskengineer.net
'@
$env:ADPPDCS = @'
EW1PRIFSADC01.adpp.adskengineer.net
EW1PRIFSADC02.adpp.adskengineer.net
UE1PRIFSADC01.adpp.adskengineer.net
UE1PRIFSADC02.adpp.adskengineer.net
UW1PRIFSADC01.adpp.adskengineer.net
UW1PRIFSADC02.adpp.adskengineer.net
'@
$env:ADPPDCIPS = @'
10.197.38.125
10.197.38.155
10.196.74.115
10.196.74.138
10.199.6.21
10.199.6.121
'@
Set-PSReadlineOption -BellStyle None

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

function Connect-Vault {
    [CmdletBinding()]
    param ()

    begin {}

    process {
        vault auth -method=ldap username=$($env:USERNAME + "admin")
    }

    end {}
}

function Get-TypeAccelerators {
    [CmdletBinding()]
    param ()

    begin {}

    process {
        [psobject].Assembly.GetType("System.Management.Automation.TypeAccelerators")::get
    }

    end {}
}

if ($IsLinux -or $IsMacOS) {
    return
}

# Remainder of profile is Windows-specific

# Chocolatey profile
$ChocolateyProfile = "$env:ChocolateyInstall\helpers\chocolateyProfile.psm1"
if (Test-Path -Path $ChocolateyProfile) {
    Import-Module "$ChocolateyProfile"
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

# function Invoke-ElevatedCommand {
#     $runningProcess = 'powershell'
#     if ((Get-Process -Id $pid).Name -eq 'powershell_ise') {
#         $runningProcess = 'powershell_ise'
#     }

#     $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
#     $principal = New-Object System.Security.Principal.WindowsPrincipal($Identity)
#     $isAdmin = $Principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)

#     if ($isAdmin) {
#         & $args
#         return
#     }

#     Start-Process -FilePath $runningProcess -Verb RunAs -WorkingDirectory $pwd.Path -ArgumentList (
#         @("-NoExit", "-Command") + $args
#     )
# }

# New-Alias -Name sudo -Value Invoke-ElevatedCommand

# function Invoke-NetView {
#     [CmdletBinding()]
#     [OutputType([string[]])]
#     param (
#         [Parameter(Mandatory=$true)]
#         [String]
#         $Path
#     )
#     begin { }
#     process {
#         [string[]](net view $Path /all | Select-Object -Skip 7 | ?{$_ -match 'disk*'} | %{$_ -match '^(.+?)\s+Disk*'|out-null;$matches[1]})
#     }
# }

$pulseLauncher = 'C:\Program Files (x86)\Common Files\Pulse Secure\Integration\pulselauncher.exe'
$displayNameToUrlMap = @{
    'APAC VPN'     = 'oahu.autodesk.com'
    'Autodesk'     = 'secure.autodesk.com'
    'EAST VPN'     = 'bigisland.autodesk.com'
    'EMEA VPN'     = 'kauai.autodesk.com'
    'Virtela'      = 'autodesk.ras.ntt.com'
    'Virtela East' = 'autodesk-ue.ras.ntt.com'
    'Virtela West' = 'autodesk.uw.ras.ntt.com'
    'WEST VPN'     = 'maui.autodesk.com'
}
$displayNameToRealmMap = @{
    'APAC VPN'     = 'autodesk.com'
    'Autodesk'     = 'autodesk.com'
    'EAST VPN'     = 'autodesk.com'
    'EMEA VPN'     = 'autodesk.com'
    'Virtela'      = 'ADPR.adskengineer.net'
    'Virtela East' = 'ADPR.adskengineer.net'
    'Virtela West' = 'ADPR.adskengineer.net'
    'WEST VPN'     = 'autodesk.com'
}

function Connect-PulseSecure {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)]
        [PSCredential]
        $Credential = (Get-Credential -Credential $env:USERNAME),

        [Parameter(Mandatory = $false)]
        [ValidateSet(
            'APAC VPN',
            'Autodesk',
            'EAST VPN',
            'EMEA VPN',
            'Virtela',
            'Virtela East',
            'Virtela West',
            'WEST VPN'
        )]
        [string]
        $DisplayName = 'Autodesk'
    )

    begin {
        $url = $displayNameToUrlMap[$DisplayName]
        $realm = $displayNameToRealmMap[$DisplayName]
        $wsl2NetAdapter = Get-NetAdapter -Name 'vEthernet (WSL)' -ErrorAction SilentlyContinue
        $isAdmin = $false
        if ($null -ne $wsl2NetAdapter) {
            $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
            $principal = New-Object System.Security.Principal.WindowsPrincipal($Identity)
            $isAdmin = $Principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
        }
    }

    process {
        if (($null -ne $wsl2NetAdapter) -and $isAdmin) {
            Disable-NetAdapter -Name 'vEthernet (WSL)' -Confirm:$false
        }

        if (($null -ne $wsl2NetAdapter) -and (-not $isAdmin)) {
            gsudo -w "Disable-NetAdapter -Name 'vEthernet (WSL)' -Confirm:`$false"
        }

        & $pulseLauncher -url $url -u $Credential.UserName -p $Credential.GetNetworkCredential().Password -r $realm

        if (($null -ne $wsl2NetAdapter) -and $isAdmin) {
            Enable-NetAdapter -Name 'vEthernet (WSL)'
        }

        if (($null -ne $wsl2NetAdapter) -and (-not $isAdmin)) {
            gsudo -w "Enable-NetAdapter -Name 'vEthernet (WSL)'"
        }
    }

    end {}
}

function Stop-PulseSecure {
    [CmdletBinding()]
    param ()

    begin {}

    process {
        & $pulseLauncher -stop
    }

    end {}
}

function Disconnect-PulseSecure {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)]
        [ValidateSet(
            'APAC VPN',
            'Autodesk',
            'EAST VPN',
            'EMEA VPN',
            'Virtela',
            'Virtela East',
            'Virtela West',
            'WEST VPN'
        )]
        [string]
        $DisplayName = 'Autodesk'
    )

    begin {
        $url = $displayNameToUrlMap[$DisplayName]
    }

    process {
        & $pulseLauncher -signout -url $url
    }

    end {}
}

function Suspend-PulseSecure {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)]
        [ValidateSet(
            'APAC VPN',
            'Autodesk',
            'EAST VPN',
            'EMEA VPN',
            'Virtela',
            'Virtela East',
            'Virtela West',
            'WEST VPN'
        )]
        [string]
        $DisplayName = 'Autodesk'
    )

    begin {
        $url = $displayNameToUrlMap[$DisplayName]
    }

    process {
        & $pulseLauncher -suspend -url $url
    }

    end {}
}

function Resume-PulseSecure {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)]
        [ValidateSet(
            'APAC VPN',
            'Autodesk',
            'EAST VPN',
            'EMEA VPN',
            'Virtela',
            'Virtela East',
            'Virtela West',
            'WEST VPN'
        )]
        [string]
        $DisplayName = 'Autodesk'
    )

    begin {
        $url = $displayNameToUrlMap[$DisplayName]
    }

    process {
        & $pulseLauncher -resume -url $url
    }

    end {}
}

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

$regularCred = Get-Secret -Name spletzr -ErrorAction SilentlyContinue
$adminCred = Get-Secret -Name spletzradmin -ErrorAction SilentlyContinue
