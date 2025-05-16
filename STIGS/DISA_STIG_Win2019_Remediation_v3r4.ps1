<#
.SYNOPSIS
    This PowerShell script applies security configuration changes according to the DISA STIG for Microsoft Windows Server 2019 (v3r4).

.DESCRIPTION
    The script implements registry and system configuration modifications required to bring a Windows Server 2019 system into compliance with several STIG items.
    It includes error handling, event log resizing, user rights configuration, and more.

.NOTES
    Author          : Sebastien Simon
    LinkedIn        : www.linkedin.com/in/sebastien-simon-632a236b
    GitHub          : github.com/sebastiensimon1
    Date Created    : 2025-05-16
    Last Modified   : 2025-05-16
    Version         : 1.0
    STIG-ID(s)      : WN19-CC-000370, WN19-CC-000040, WN19-SO-000160, WN19-SO-000360, WN19-AC-000070, WN19-SO-000310, WN19-CC-000280, WN19-UR-000140, WN19-AU-000250, etc.

.TESTED ON
    Date(s) Tested  : 2025-05-16
    Tested By       : Sebastien Simon
    Systems Tested  : Windows Server 2019
    PowerShell Ver. : 5.1

.USAGE
    Open PowerShell as Administrator and execute:
    PS C:\> .\DISA_STIG_Win2019_Remediation_v3r4.ps1
#>

#region Helper Function
function Set-RegKeyWithCreate {
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
        Write-Warning "Failed to set registry value: $_"
    }
}
#endregion

#region System Configuration
Set-RegKeyWithCreate -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name "fSecureRPCCheck" -Value 1
Set-RegKeyWithCreate -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -Name "DisableIPSourceRouting" -Value 2
Set-RegKeyWithCreate -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters" -Name "DisableIPSourceRouting" -Value 2
Set-RegKeyWithCreate -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" -Name "RequireSecuritySignature" -Value 1
Set-RegKeyWithCreate -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "RequireSecuritySignature" -Value 1
Set-RegKeyWithCreate -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "EnableSecuritySignature" -Value 1
Set-RegKeyWithCreate -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\FIPSAlgorithmPolicy" -Name "Enabled" -Value 1
#endregion

#region Account Policies
try {
    net accounts /MINPWLEN:14 /LOCKOUTDURATION:15 /LOCKOUTTHRESHOLD:3 /UNIQUEPW:24 /LOCKOUTWINDOW:15 2>&1 | Out-Null
}
catch {
    Write-Warning "Failed to set account policies: $_"
}
Set-RegKeyWithCreate -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0" -Name "NtlmMinClientSec" -Value 537395200
Set-RegKeyWithCreate -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0" -Name "RestrictSendingNTLMTraffic" -Value 2
#endregion

#region Event Logs
try {
    wevtutil set-log Security /ms:196608000 2>&1 | Out-Null
    wevtutil set-log Application /ms:32768000 2>&1 | Out-Null
    wevtutil set-log System /ms:32768000 2>&1 | Out-Null
}
catch {
    Write-Warning "Failed to configure event logs: $_"
}
#endregion

#region User Rights & Audit Policies
try {
    secedit /configure /cfg $env:SystemRoot\inf\defltbase.inf /db defltbase.sdb /verbose 2>&1 | Out-Null
}
catch {
    Write-Warning "Failed to configure user rights assignments: $_"
}
try {
    auditpol /set /subcategory:"Removable Storage" /success:enable /failure:enable 2>&1 | Out-Null
}
catch {
    Write-Warning "Failed to configure audit policies: $_"
}
#endregion

#region User Interface & Session Security
Set-RegKeyWithCreate -Path "HKCU:\Control Panel\Desktop" -Name "ScreenSaveTimeOut" -Value 900 -Type String
Set-RegKeyWithCreate -Path "HKCU:\Control Panel\Desktop" -Name "ScreenSaverIsSecure" -Value 1
Set-RegKeyWithCreate -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLUA" -Value 1
Set-RegKeyWithCreate -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ConsentPromptBehaviorAdmin" -Value 1
Set-RegKeyWithCreate -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ConsentPromptBehaviorUser" -Value 0
#endregion

#region Network & Protocol Security
try {
    Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart -ErrorAction Stop | Out-Null
    Set-RegKeyWithCreate -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "SMB1" -Value 0
}
catch {
    Write-Warning "Failed to disable SMBv1: $_"
}
Set-RegKeyWithCreate -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "DoNotConnectToWindowsUpdateInternetLocations" -Value 1
#endregion

#region PowerShell Security
Set-RegKeyWithCreate -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" -Name "EnableTranscripting" -Value 1
Set-RegKeyWithCreate -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Name "EnableScriptBlockLogging" -Value 1
Set-RegKeyWithCreate -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" -Name "EnableInvocationHeader" -Value 1
Set-RegKeyWithCreate -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" -Name "OutputDirectory" -Value "C:\PS_Transcripts" -Type String
#endregion

#region Device Control & Misc
Set-RegKeyWithCreate -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name "fDisableCdm" -Value 1
Set-RegKeyWithCreate -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" -Name "UseLogonCredential" -Value 0
#endregion

#region Final Configurations
try {
    Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True -ErrorAction Stop
}
catch {
    Write-Warning "Failed to configure firewall: $_"
}
gpupdate /force 2>&1 | Out-Null

Write-Host "Remediation complete. System reboot required for some changes." -ForegroundColor Yellow
Write-Host "Please manually verify:" -ForegroundColor Cyan
Write-Host "- Certificate configurations (WN19-PK-* items)"
Write-Host "- Local user rights assignments"
Write-Host "- Physical device restrictions"
Write-Host "- Third-party software configurations"
#endregion
