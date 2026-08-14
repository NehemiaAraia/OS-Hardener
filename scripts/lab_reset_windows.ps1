# LAB ONLY — this WEAKENS the machine it runs on.
#
# A fresh Windows Server 2022 AMI already passes several controls, so a
# before/after demo has nothing to show. This reverts a handful of settings to a
# realistic unhardened state so remediation has real work to do.
#
# This must never run anywhere but a throwaway lab instance. It refuses unless
# you pass -IUnderstandThisWeakensThisHost and confirm the hostname.
#
#   .\lab_reset_windows.ps1 -IUnderstandThisWeakensThisHost

param(
    [switch]$IUnderstandThisWeakensThisHost
)

$ErrorActionPreference = "Stop"

if (-not $IUnderstandThisWeakensThisHost) {
    Write-Host @"
refusing to run.

This script deliberately weakens security settings so the hardening demo has
failing controls to fix. It is only appropriate on a disposable lab VM.

To proceed:
  .\lab_reset_windows.ps1 -IUnderstandThisWeakensThisHost
"@ -ForegroundColor Yellow
    exit 1
}

Write-Host "host: $env:COMPUTERNAME"
$answer = Read-Host "weaken THIS host for a hardening demo? type the hostname to confirm"
if ($answer -ne $env:COMPUTERNAME) {
    Write-Host "hostname did not match, aborting" -ForegroundColor Red
    exit 1
}

Write-Host "[*] enabling SMBv1 (this is the point of the demo)..."
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

# the firewall is deliberately LEFT ON. Turning it off on a cloud instance you
# reach over the network is how you lose access to the box mid-demo.
Write-Host "[*] firewall left enabled on purpose (turning it off risks your own access)"

Write-Host ""
Write-Host "[*] done. this host is now deliberately non-compliant."
Write-Host "    verify:  python main.py scan --target windows --host <ip>"
Write-Host "    restore: python main.py remediate --target windows --host <ip> --apply"
