# Run once on the Windows host, logged in as the default Administrator.
# Creates the scanner service account and enables WinRM over HTTPS only.
# Usage:  .\bootstrap_windows.ps1 -OperatorCidr 203.0.113.4/32

param(
    [Parameter(Mandatory = $true)][string]$OperatorCidr,
    [string]$AccountName = "svc-hardening-scanner"
)

$ErrorActionPreference = "Stop"

# password is generated here and shown once — it goes into the operator's env
# vars (WINRM_PASS), never into the repo
Add-Type -AssemblyName System.Web
$password = [System.Web.Security.Membership]::GeneratePassword(24, 6)
$secure = ConvertTo-SecureString $password -AsPlainText -Force

if (Get-LocalUser -Name $AccountName -ErrorAction SilentlyContinue) {
    Set-LocalUser -Name $AccountName -Password $secure
} else {
    New-LocalUser -Name $AccountName -Password $secure -PasswordNeverExpires -AccountNeverExpires `
        -Description "Least-privilege account for the hardening scanner" | Out-Null
}

# Remote Management Users grants WinRM access without local admin rights
Add-LocalGroupMember -Group "Remote Management Users" -Member $AccountName -ErrorAction SilentlyContinue
# read access to the event log for the audit checks, still not admin
Add-LocalGroupMember -Group "Event Log Readers" -Member $AccountName -ErrorAction SilentlyContinue

Write-Host "[*] account $AccountName created"

# --- WinRM over HTTPS (5986) only -------------------------------------------
$hostname = [System.Net.Dns]::GetHostByName($env:COMPUTERNAME).HostName
$cert = New-SelfSignedCertificate -DnsName $hostname -CertStoreLocation Cert:\LocalMachine\My

# the HTTP listener may not exist on a re-run; a native command's stderr would
# still be terminating under ErrorActionPreference=Stop, so isolate it
try {
    $ErrorActionPreference = "Continue"
    winrm delete winrm/config/Listener?Address=*+Transport=HTTP 2>&1 | Out-Null
} finally {
    $ErrorActionPreference = "Stop"
}

New-Item -Path WSMan:\localhost\Listener -Transport HTTPS -Address * `
    -CertificateThumbPrint $cert.Thumbprint -Force | Out-Null

# refuse unencrypted traffic and basic auth outright
Set-Item -Path WSMan:\localhost\Service\AllowUnencrypted -Value $false
Set-Item -Path WSMan:\localhost\Service\Auth\Basic -Value $false

New-NetFirewallRule -DisplayName "WinRM HTTPS (operator only)" -Direction Inbound `
    -LocalPort 5986 -Protocol TCP -Action Allow -RemoteAddress $OperatorCidr | Out-Null

Write-Host "[*] WinRM listening on 5986 (HTTPS), 5985 removed"
Write-Host ""
Write-Host "set these on the scanning machine, they are not stored anywhere:"
Write-Host "  export WINRM_USER='$AccountName'"
Write-Host "  export WINRM_PASS='$password'"
