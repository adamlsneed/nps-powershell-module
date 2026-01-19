# SbPAM / Netwrix Privilege Secure - PowerShell Quick Reference

## Module Files
- `SbPAMAPI-Enhanced.psm1` - Main module (77 KB, 39 functions)
- `SbPAMAPI-Enhanced.psd1` - Module manifest
- `NPS-Module.psm1` - Alternative NPS module (58 KB, 34 functions)

## Installation
```powershell
# Copy to PowerShell modules directory
Copy-Item SbPAMAPI-Enhanced.* "$env:USERPROFILE\Documents\PowerShell\Modules\SbPAMAPI-Enhanced\"

# Or import directly
Import-Module ./SbPAMAPI-Enhanced.psm1
```

## Getting Help
```powershell
# Full help with all details
Get-Help Get-SbPAMToken -Full

# Just examples
Get-Help Start-SbPAMActivitySession -Examples

# Parameter details
Get-Help Get-SbPAMCredential -Parameter *

# List all cmdlets
Get-Command -Module SbPAMAPI-Enhanced
```

## Authentication Examples

### Basic Authentication
```powershell
$token = Get-SbPAMToken -Uri "https://sbpam.company.com" `
    -Username "admin" -Password "P@ssw0rd"
```

### With MFA/TOTP
```powershell
$token = Get-SbPAMMfaToken -Uri "https://sbpam.company.com" `
    -Username "admin" -Password "P@ssw0rd" -TotpSecret "BASE32SECRET"
```

### Application User Token
```powershell
$token = Get-SbPAMAppUserToken -Uri "https://sbpam.company.com" `
    -ClientId "app-client-id" -ClientSecret "secret"
```

## Common Operations

### List Managed Resources
```powershell
Get-SbPAMManagedResource -Token $token | Format-Table Name, DnsHostName
```

### Search Credentials
```powershell
Get-SbPAMCredential -Token $token -CredentialName "Admin-Server01"
Get-SbPAMCredential -Token $token -CredentialAccount "administrator" -CredentialResource "DOMAIN"
```

### Start Activity Session
```powershell
$session = Start-SbPAMActivitySession -Token $token `
    -ActivityName "RDP" -ResourceName "Server01" -CredentialName "Admin-Server01"

# Get password for session
$password = Get-SbPAMActivitySessionPassword -Token $token -Id $session.Id
```

### Stop Session
```powershell
Stop-SbPAMActivitySession -Token $token -Id $session.Id
```

### SSH Certificate Operations
```powershell
# Generate new SSH certificate
New-SbPAMUserSshCertificate -UserId $userId -Token $token `
    -KeyGenAlgorithm "Ed25519" -AutoGenPassphrase $true

# Get existing certificate
Get-SbPAMUserSshCertificate -UserId $userId -Token $token
```

### Search Session Content
```powershell
# Search active sessions
Search-SbPAMActiveSession -SearchFilter "sudo" -Key "StdIn" -Token $token

# Search historical sessions
Search-SbPAMHistoricalSession -SearchFilter "password" -Token $token
```

### Cisco Device Access
```powershell
$enablePwd = Get-SbPAMCiscoEnablePassword -Token $token -SessionId $session.Id
```

## Function Categories

| Category | Functions |
|----------|----------|
| Authentication | Get-SbPAMToken, Get-SbPAMUserToken, Get-SbPAMAppUserToken, Get-SbPAMMfaToken, Convert-SbPAMToken, Get-SbPAMTotp |
| Certificates | Get-SbPAMCertificate, Get-SbPAMNixCertificate |
| Access Control | Get-SbPAMUserPolicy, Get-SbPAMAccessControlPolicy |
| Credentials | Get-SbPAMCredential, Get-SbPAMCredentialTypes, Get-SbPAMAuthenticationMethodTypes |
| Sessions | Get-SbPAMActivitySession, Start-SbPAMActivitySession, Stop-SbPAMActivitySession, Get-SbPAMActivitySessionPassword, Get-SbPAMActivitySessionSummary, Get-SbPAMActivitySessionConfiguration, Get-SbPAMActivitySessionCount |
| Resources | Get-SbPAMActivitySessionResource, Get-SbPAMManagedResource, Get-SbPAMManagedResourceSshFingerprint, Set-SbPAMManagedResourceTrustThumbprint |
| SSH | Get-SbPAMSSHKeyGenAlgorithm, New-SbPAMUserSshCertificate, Get-SbPAMCredentialSshCertificate, Get-SbPAMUserSshCertificate, Get-SbPAMSshCertificateByDomainUser, Get-SbPAMSshCertificateByUser |
| Domain | Get-SbPAMDomain |
| Search | Search-SbPAMActiveSession, Search-SbPAMHistoricalSession |
| Cisco | Get-SbPAMCiscoEnablePassword, Get-SbPAMCiscoEnablePasswordByCredential |
| System | Get-SbPAMSettings, Get-SbPAMVersion, Get-SbPAMHealth |
| Helpers | Invoke-SbPAMRest |
