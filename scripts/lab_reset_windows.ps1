# LAB ONLY — this WEAKENS the machine it runs on.
#
# A fresh Windows Server 2022 AMI already passes several controls, so a
# before/after run has nothing to fix. This reverts a handful of settings to a
# realistic unhardened state so remediation has real work to do.
#
# This must never run anywhere but a throwaway lab instance. It refuses unless
# you pass -IUnderstandThisWeakensThisHost and confirm the hostname.
#
#   .\lab_reset_windows.ps1 -IUnderstandThisWeakensThisHost

param(
    [switch]$IUnderstandThisWeakensThisHost,
    # Non-interactive equivalent of the prompt below: you still have to know and
    # supply the exact hostname, which is the point of the check. Read-Host
    # blocks forever over WinRM, where there is no stdin to answer it.
    [string]$ConfirmHostname
)

$ErrorActionPreference = "Stop"

if (-not $IUnderstandThisWeakensThisHost) {
    Write-Host @"
refusing to run.

This script deliberately weakens security settings so there are failing controls
to test remediation against. It is only appropriate on a disposable lab VM.

To proceed:
  .\lab_reset_windows.ps1 -IUnderstandThisWeakensThisHost
"@ -ForegroundColor Yellow
    exit 1
}

Write-Host "host: $env:COMPUTERNAME"
if ($ConfirmHostname) {
    $answer = $ConfirmHostname
} else {
    $answer = Read-Host "weaken THIS host for testing? type the hostname to confirm"
}
if ($answer -ne $env:COMPUTERNAME) {
    Write-Host "hostname did not match, aborting" -ForegroundColor Red
    exit 1
}

Write-Host "[*] enabling SMBv1..."
# -NoRestart: the scanner reports the reboot requirement rather than forcing it
Enable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart -ErrorAction SilentlyContinue | Out-Null
New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" `
    -Name SMB1 -Value 1 -PropertyType DWORD -Force | Out-Null

Write-Host "[*] weakening the password policy..."
net accounts /minpwlen:7 | Out-Null

Write-Host "[*] disabling logon failure auditing..."
auditpol /set /subcategory:"Logon" /success:enable /failure:disable | Out-Null

Write-Host "[*] starting Remote Registry..."
Set-Service -Name RemoteRegistry -StartupType Automatic -ErrorAction SilentlyContinue
Start-Service -Name RemoteRegistry -ErrorAction SilentlyContinue

Write-Host "[*] enabling the Guest account..."
Enable-LocalUser -Name Guest -ErrorAction SilentlyContinue

# Turning the firewall OFF cannot cost us access — it stops filtering. The risk
# is on the way back UP, so remediation re-enables all three profiles and the
# WinRM HTTPS allow-rule created at bootstrap is what keeps the session alive.
Write-Host "[*] disabling the firewall on all profiles..."
Set-NetFirewallProfile -Profile Domain,Private,Public -Enabled False

Write-Host ""
Write-Host "[*] done. this host is now deliberately non-compliant."
Write-Host "    verify:  python main.py scan --target windows --host <ip>"
Write-Host "    restore: python main.py remediate --target windows --host <ip> --apply"
