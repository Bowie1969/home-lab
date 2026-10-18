# setup-dc.ps1 — one-time provisioning for the Keystone domain controller.
# Run via autounattend FirstLogonCommands after Windows Server install. Creates
# keystone.local, a kerberoastable service account, and an AS-REP-roastable user.
# The weak passwords are intentional: they are the attack surface for ad-kerberos.

$ErrorActionPreference = "Stop"

# 1. Promote to a domain controller for keystone.local
Install-WindowsFeature AD-Domain-Services -IncludeManagementTools
$safe = ConvertTo-SecureString "S@fe-Mode-2026" -AsPlainText -Force
Install-ADDSForest -DomainName "keystone.local" -DomainNetbiosName "KEYSTONE" `
    -SafeModeAdministratorPassword $safe -InstallDns -Force -NoRebootOnCompletion

# (reboot happens; the remainder runs on the second FirstLogonCommand pass)

Import-Module ActiveDirectory

# 2. Kerberoastable service account: has an SPN + a weak, crackable password.
New-ADUser -Name "svc_sql" -SamAccountName "svc_sql" `
    -AccountPassword (ConvertTo-SecureString "Summer2026" -AsPlainText -Force) `
    -Enabled $true -PasswordNeverExpires $true
setspn -s MSSQLSvc/sql.keystone.local:1433 svc_sql

# 3. AS-REP-roastable user: Kerberos pre-auth disabled.
New-ADUser -Name "John Doe" -SamAccountName "j.doe" `
    -AccountPassword (ConvertTo-SecureString "Autumn!2026" -AsPlainText -Force) `
    -Enabled $true
Set-ADAccountControl -Identity "j.doe" -DoesNotRequirePreAuth $true

# 4. Service account from the leaked handover doc (share-anon) is a real,
#    privileged account so that credential path also works.
New-ADUser -Name "svc_backup" -SamAccountName "svc_backup" `
    -AccountPassword (ConvertTo-SecureString "Backup`$pr1ng2026" -AsPlainText -Force) `
    -Enabled $true -PasswordNeverExpires $true
Add-ADGroupMember -Identity "Backup Operators" -Members "svc_backup"

# 5. Flag placeholder on the admin desktop; reset.sh re-stamps the rotated value.
"KEYSTONE{domain-admin-PLACEHOLDER}" | Out-File "C:\Users\Administrator\Desktop\flag.txt"

# 6. Vault break-glass credential: left on the admin desktop so a Domain
#    Admin (or DCSync'd) compromise can authenticate to the DATA-tier vault.
#    The vault accepts this token alongside every other branch's token.
"ks-vault-da-3f9a6c" | Out-File "C:\Users\Administrator\Desktop\vault-break-glass.txt"

Write-Output "keystone.local provisioned: svc_sql (kerberoast), j.doe (asrep), svc_backup (handover)"
