# Run from an elevated PowerShell prompt inside an owner-supplied Windows 7 SP1 VM.
# This prepares the lab service; it does not install, remove, or supply Windows updates.
$ErrorActionPreference = "Stop"

$os = Get-WmiObject Win32_OperatingSystem
if ($os.Caption -notmatch "Windows 7" -or $os.ServicePackMajorVersion -ne 1) {
    throw "Expected Windows 7 SP1; found $($os.Caption) SP$($os.ServicePackMajorVersion)"
}

$knownFixes = @("KB4012212", "KB4012215")
$installed = @(Get-HotFix | ForEach-Object { $_.HotFixID.ToUpperInvariant() })
$present = @($knownFixes | Where-Object { $installed -contains $_ })
if ($present.Count -gt 0) {
    throw "MS17-010 fix detected ($($present -join ', ')); use a clean, authorized lab image"
}

Set-Service -Name LanmanServer -StartupType Automatic
Start-Service -Name LanmanServer
netsh advfirewall firewall set rule group="File and Printer Sharing" new enable=Yes | Out-Null

New-Item -ItemType Directory -Path C:\Keystone -Force | Out-Null
Set-Content -Path C:\Keystone\flag.txt -Value "KEYSTONE{ms17-010-system-PLACEHOLDER}"
$acl = Get-Acl C:\Keystone\flag.txt
$acl.SetAccessRuleProtection($true, $false)
$rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
    "NT AUTHORITY\SYSTEM", "FullControl", "Allow")
$acl.SetAccessRule($rule)
Set-Acl C:\Keystone\flag.txt $acl

# Vault break-glass: SYSTEM-only so only a successful MS17-010 compromise reads it.
Set-Content -Path C:\Keystone\vault-break-glass.txt -Value "ks-vault-eternal-6b3f7d"
$acl2 = Get-Acl C:\Keystone\vault-break-glass.txt
$acl2.SetAccessRuleProtection($true, $false)
$rule2 = New-Object System.Security.AccessControl.FileSystemAccessRule(
    "NT AUTHORITY\SYSTEM", "FullControl", "Allow")
$acl2.SetAccessRule($rule2)
Set-Acl C:\Keystone\vault-break-glass.txt $acl2

Write-Host "Prepared win7-finance. Final acceptance still requires an isolated MS17-010 scanner check."
Write-Host "Do not set runtime.json ready=true until the clean snapshot and guest-agent checks pass."
