# Run from an elevated PowerShell prompt inside an owner-supplied Windows Server
# 2025 VM. Prepares the lab service; it does not install, remove, or supply any
# Windows update. Edit $TargetKB to the KB that supersedes the specific SMB CVE
# the owner wants to leave exposed (match the manifest `vulnerability.cves`
# selection), then verify `vulnerability.fixed_in` and `.source` in the manifest.
$ErrorActionPreference = "Stop"

# ---- Target identity ------------------------------------------------------
$os = Get-CimInstance Win32_OperatingSystem
if ($os.Caption -notmatch "Windows Server 2025") {
    throw "Expected Windows Server 2025; found $($os.Caption)"
}

# ---- Patch pin ------------------------------------------------------------
# Replace with the KB that fixes the targeted SMB CVE for this build.
$TargetKB = "KB-PLACEHOLDER-FILL-ME-IN"
if ($TargetKB -like "KB-PLACEHOLDER*") {
    Write-Warning "Target KB not pinned; edit prepare-target.ps1 before setting runtime.json ready=true."
} else {
    $installed = @(Get-HotFix | ForEach-Object { $_.HotFixID.ToUpperInvariant() })
    if ($installed -contains $TargetKB.ToUpperInvariant()) {
        throw "Targeted CVE's fix $TargetKB is installed; roll back to a clean, authorized lab image."
    }
}

# ---- SMB stack ------------------------------------------------------------
# Server 2025 ships SMBv3 by default. Keep SMBv3 on; leave the specific
# unpatched sub-feature exposed by *not* applying $TargetKB. SMBv1 remains
# disabled unless the chosen CVE explicitly requires it (and even then only
# with the operator's documented sign-off).
Set-Service -Name LanmanServer -StartupType Automatic
Start-Service -Name LanmanServer
New-NetFirewallRule -DisplayName "SMB-In-445-keystone" `
    -Direction Inbound -Protocol TCP -LocalPort 445 -Action Allow `
    -ErrorAction SilentlyContinue | Out-Null

# ---- Flag planting --------------------------------------------------------
New-Item -ItemType Directory -Path C:\Keystone -Force | Out-Null
Set-Content -Path C:\Keystone\flag.txt -Value "KEYSTONE{win2025-smb-system-PLACEHOLDER}"
$acl = Get-Acl C:\Keystone\flag.txt
$acl.SetAccessRuleProtection($true, $false)
$rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
    "NT AUTHORITY\SYSTEM", "FullControl", "Allow")
$acl.SetAccessRule($rule)
Set-Acl C:\Keystone\flag.txt $acl

# Vault break-glass: SYSTEM-only so only a successful SMB RCE compromise reads it.
Set-Content -Path C:\Keystone\vault-break-glass.txt -Value "ks-vault-win2025-2f8c19"
$acl2 = Get-Acl C:\Keystone\vault-break-glass.txt
$acl2.SetAccessRuleProtection($true, $false)
$rule2 = New-Object System.Security.AccessControl.FileSystemAccessRule(
    "NT AUTHORITY\SYSTEM", "FullControl", "Allow")
$acl2.SetAccessRule($rule2)
Set-Acl C:\Keystone\vault-break-glass.txt $acl2

# ---- Guest agent + cloud-init marker --------------------------------------
# Proxmox qemu-guest-agent on Windows: install the virtio-win guest-agent MSI
# BEFORE snapshot. Set-Service here just makes sure it is set to auto-start if
# the MSI is already present.
Get-Service -Name "QEMU-GA" -ErrorAction SilentlyContinue | ForEach-Object {
    Set-Service -Name $_.Name -StartupType Automatic
    Start-Service -Name $_.Name
}

Write-Host "Prepared win2025-smb. Final acceptance still requires:"
Write-Host " - Get-HotFix shows the targeted KB absent"
Write-Host " - Clean snapshot captured"
Write-Host " - qemu-guest-agent responding to Proxmox"
Write-Host "Only then set modules/win2025-smb/runtime.json ready=true."
