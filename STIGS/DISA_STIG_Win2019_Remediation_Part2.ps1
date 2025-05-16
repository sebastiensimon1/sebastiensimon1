<#
.SYNOPSIS
    This script continues DISA STIG remediation by applying security configurations with progress monitoring.

.DESCRIPTION
    Enhances user visibility into the remediation process through progress bars. Applies registry hardening, security policy enforcement, certificate trust store updates, and other system configurations based on DISA STIG for Windows Server 2019 (v3r4).

.NOTES
    Author          : Sebastien Simon
    LinkedIn        : https://www.linkedin.com/in/sebastien-simon-632a236b/
    GitHub          : github.com/sebastiensimon1
    Date Created    : 2025-05-16
    Last Modified   : 2025-05-16
    Version         : 1.0
    STIG-ID(s)      : WN19-CC-000370, WN19-CC-000160, WN19-SO-000160, WN19-AU-000280, WN19-PK-000005, etc.

.TESTED ON
    Date(s) Tested  : 2025-05-16
    Tested By       : Sebastien Simon
    Systems Tested  : Windows Server 2019
    PowerShell Ver. : 5.1

.USAGE
    Run as Administrator:
    PS C:\> .\DISA_STIG_Win2019_Remediation_Part2.ps1
#>

#region Helper Functions

function Show-Progress {
    param(
        [string]$Activity,
        [string]$Status,
        [int]$Percent
    )
    Write-Progress -Activity $Activity -Status $Status -PercentComplete $Percent
    Start-Sleep -Milliseconds 200  # Visual feedback
}

function Safe-Secedit {
    param(
        [string]$Command
    )
    Show-Progress -Activity "Applying Security Policies" -Status $Command -Percent 10
    $process = Start-Process secedit -ArgumentList $Command -NoNewWindow -PassThru -Wait
    if ($process.ExitCode -ne 0) {
        Write-Warning "secedit failed with exit code $($process.ExitCode)"
    }
}

function Set-RegistryProperty {
    param(
        [string]$Path,
        [string]$Name,
        [object]$Value,
        [string]$Type = "DWord"
    )
    try {
        if (-not (Test-Path $Path)) {
            New-Item -Path $Path -Force -ErrorAction Stop | Out-Null
        }
        Set-ItemProperty -Path $Path -Name $Name -Value $Value -Type $Type -ErrorAction Stop
    }
    catch {
        Write-Warning "Failed to set registry property: $_"
    }
}

#endregion

#region Initialization
Show-Progress -Activity "Starting STIG Remediation" -Status "Initializing..." -Percent 5
$ErrorActionPreference = "SilentlyContinue"
$startTime = Get-Date
#endregion

#region Registry Modifications
Show-Progress -Activity "Configuring Registry" -Status "Terminal Services" -Percent 15
Set-RegistryProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name "fEncryptRPCTraffic" -Value 1

Show-Progress -Activity "Configuring Registry" -Status "Client Signing" -Percent 20
Set-RegistryProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" -Name "RequireSecuritySignature" -Value 1
#endregion

#region Security Policy Enforcement
Show-Progress -Activity "Updating Security Policies" -Status "Password Policy" -Percent 30
Safe-Secedit "/export /cfg $env:temp\secpol.cfg"
Safe-Secedit "/configure /db $env:temp\secedit.sdb /cfg $env:temp\secpol.cfg /areas SECURITYPOLICY"
#endregion

#region Certificate Operations
Show-Progress -Activity "Certificate Configuration" -Status "Checking Certs" -Percent 50
if (Test-Path "C:\Certs") {
    Get-ChildItem "C:\Certs\DoD_Root_CA_*.cer" | ForEach-Object {
        try {
            Import-Certificate -FilePath $_.FullName -CertStoreLocation Cert:\LocalMachine\Root | Out-Null
        } catch {
            Write-Warning "Failed to import certificate: $_"
        }
    }
}
#endregion

#region User Account Management
Show-Progress -Activity "User Configuration" -Status "Admin Account" -Percent 70
try {
    if (Get-LocalUser -Name "Administrator" -ErrorAction SilentlyContinue) {
        Set-LocalUser -Name "Administrator" -PasswordNeverExpires $false
    }
}
catch {
    Write-Warning "Failed to configure local user account: $_"
}
#endregion

#region Event Log Configuration
Show-Progress -Activity "Final Configuration" -Status "Event Log Size" -Percent 85
try {
    wevtutil set-log Security /ms:196608 | Out-Null
}
catch {
    Write-Warning "Failed to set Security log size"
}
#endregion

#region Completion
Show-Progress -Activity "Completing Process" -Status "Finalizing" -Percent 95
$ErrorActionPreference = "Continue"
$totalTime = (Get-Date) - $startTime

Write-Host "`nRemediation completed in $($totalTime.ToString('hh\:mm\:ss'))"
Write-Host "System reboot REQUIRED for all changes to take effect" -ForegroundColor Yellow
#endregion
