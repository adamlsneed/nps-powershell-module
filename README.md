# Netwrix Privilege Secure (NPS) PowerShell Modules

[![PowerShell](https://img.shields.io/badge/PowerShell-5.1%2B-blue.svg)](https://docs.microsoft.com/en-us/powershell/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

PowerShell modules for automating Netwrix Privilege Secure (formerly Stealthbits PAM) operations.

## 📁 Modules Included

| Module | Functions | Description |
|--------|-----------|-------------|
| `NPS-Module-Complete.psm1` | **66 cmdlets** | Complete NPS module with ALL commands and full Get-Help documentation |
| `SbPAMAPI-Enhanced.psm1` | **39 functions** | Original Stealthbits PAM module with enhanced help documentation |

### Which Module Should I Use?

| Use Case | Recommended |
|----------|-------------|
| **New projects** | `NPS-Module-Complete.psm1` - Has everything with modern NPS naming |
| **Existing SbPAM scripts** | `SbPAMAPI-Enhanced.psm1` - Compatible with original function names |
| **Learning the API** | `NPS-Module-Complete.psm1` - Better organized with full documentation |

---

## 🚀 Quick Start

### Installation

```powershell
# Clone the repository
git clone https://github.com/adamlsneed/nps-powershell-module.git

# Import the complete module (recommended)
Import-Module ./NPS-Module-Complete.psm1

# Or import the original Stealthbits module
Import-Module ./SbPAMAPI-Enhanced.psm1
```

### Authentication

```powershell
# Connect to NPS server (two-step MFA authentication)
Connect-NPSServer -Server "https://your-nps-server.com" `
                  -Username "admin" `
                  -Password "YourPassword" `
                  -MfaCode "123456"

# Verify connection
Test-NPSConnection
```

### Basic Usage

```powershell
# Get all managed resources
Get-NPSManagedResource

# Get credentials
Get-NPSCredential

# Get activity sessions
Get-NPSActivitySession

# Start a new activity session
Start-NPSActivitySession -ResourceId "xxx" -CredentialId "yyy"

# Check system health
Get-NPSHealth
Get-NPSVersion
```

---

## 📚 NPS-Module-Complete (66 Functions)

### Authentication & Tokens (8)
| Cmdlet | Description |
|--------|-------------|
| `Connect-NPSServer` | Authenticate to NPS with MFA |
| `Disconnect-NPSServer` | End current session |
| `Test-NPSConnection` | Verify connection status |
| `Convert-NPSToken` | Decode JWT token payload |
| `Get-NPSToken` | Get authentication token |
| `Get-NPSMfaToken` | Get MFA token |
| `Get-NPSUserToken` | Get user-specific token |
| `Get-NPSAppUserToken` | Get application user token |

### Activity & Sessions (13)
| Cmdlet | Description |
|--------|-------------|
| `Get-NPSActivity` | List activities |
| `Get-NPSActivityGroup` | List activity groups |
| `Get-NPSActivitySession` | List activity sessions |
| `Get-NPSActivitySessionLog` | Get session logs |
| `Get-NPSActivitySessionConfiguration` | Get session config |
| `Get-NPSActivitySessionCount` | Get session count |
| `Get-NPSActivitySessionPassword` | Get session password |
| `Get-NPSActivitySessionResource` | Get session resources |
| `Get-NPSActivitySessionSummary` | Get session summary |
| `Start-NPSActivitySession` | Start new session |
| `Stop-NPSActivitySession` | Stop active session |
| `Search-NPSActiveSession` | Search active sessions |
| `Search-NPSHistoricalSession` | Search historical sessions |

### Credentials (4)
| Cmdlet | Description |
|--------|-------------|
| `Get-NPSCredential` | List stored credentials |
| `Get-NPSCredentialTypes` | Get credential types |
| `Get-NPSCredentialSshCertificate` | Get SSH certificate for credential |
| `Get-NPSCiscoEnablePasswordByCredential` | Get Cisco enable password |

### Resources & Accounts (7)
| Cmdlet | Description |
|--------|-------------|
| `Get-NPSManagedResource` | List managed resources |
| `Get-NPSManagedAccount` | List managed accounts |
| `Get-NPSHost` | List hosts |
| `Get-NPSHostScanJob` | List host scan jobs |
| `Get-NPSManagedResourceSshFingerprint` | Get SSH fingerprint |
| `Set-NPSManagedResourceTrustThumbprint` | Set trust thumbprint |
| `Export-NPSManagedResources` | Export resources to CSV |

### Actions & Jobs (6)
| Cmdlet | Description |
|--------|-------------|
| `Get-NPSActionGroup` | List action groups |
| `Get-NPSActionJob` | List action jobs |
| `Get-NPSActionQueue` | List queued actions |
| `Get-NPSActionService` | List action services |
| `Get-NPSActionTemplate` | List action templates |
| `Watch-NPSActionQueue` | Monitor action queue |

### SSH & Certificates (7)
| Cmdlet | Description |
|--------|-------------|
| `Get-NPSCertificate` | Get certificates |
| `Get-NPSNixCertificate` | Get Unix/Linux certificates |
| `Get-NPSSSHKeyGenAlgorithm` | Get SSH key algorithms |
| `Get-NPSSshCertificateByDomainUser` | Get SSH cert by domain user |
| `Get-NPSSshCertificateByUser` | Get SSH cert by user |
| `Get-NPSUserSshCertificate` | Get user SSH certificate |
| `New-NPSUserSshCertificate` | Create new SSH certificate |

### System & Configuration (6)
| Cmdlet | Description |
|--------|-------------|
| `Get-NPSHealth` | Check system health |
| `Get-NPSVersion` | Get NPS version |
| `Get-NPSLicenseInfo` | Get license information |
| `Get-NPSPlatform` | List supported platforms |
| `Get-NPSSettings` | Get system settings |
| `Test-NPSServices` | Test all services |

### Policies & Security (15)
| Cmdlet | Description |
|--------|-------------|
| `Get-NPSAccessControlPolicy` | List access policies |
| `Get-NPSApprovalWorkflow` | List approval workflows |
| `Get-NPSProtectionPolicy` | List protection policies |
| `Get-NPSScheduledChangePolicy` | List scheduled change policies |
| `Get-NPSUserPolicy` | Get user policies |
| `Get-NPSAuthenticationMethodTypes` | Get auth method types |
| `Get-NPSCiscoEnablePassword` | Get Cisco enable password |
| `Get-NPSDomain` | List domains |
| `Get-NPSLog` | Get logs |
| `Get-NPSSecretVault` | List secret vaults |
| `Get-NPSServiceRegistration` | List service registrations |
| `Get-NPSTotp` | Get TOTP codes |
| `Get-NPSUser` | List users |
| `Get-NPSWebsite` | List websites |
| `Invoke-NPSApi` | Low-level API wrapper |

---

## 📖 Getting Help

```powershell
# Get help for any cmdlet
Get-Help Connect-NPSServer -Full
Get-Help Get-NPSManagedResource -Examples
Get-Help Start-NPSActivitySession -Parameter *

# List all available cmdlets
Get-Command -Module NPS-Module-Complete
```

---

## 🔐 Authentication Flow

NPS uses a two-step MFA authentication:

1. **POST /signinBody** - Initial auth with `Login` and `Password` → Returns pre-MFA token
2. **POST /signin2fa** - MFA verification with code → Returns full JWT token

```powershell
# The Connect-NPSServer cmdlet handles this automatically
Connect-NPSServer -Server $server -Username $user -Password $pass -MfaCode $mfa
```

---

## 🔗 Related Projects

- [NPS API Documentation](https://github.com/adamlsneed/nps-api-documentation) - Complete API reference with 55+ endpoints

---

## 📋 Requirements

- PowerShell 5.1 or later (PowerShell 7+ recommended)
- Network access to NPS server
- Valid NPS credentials with MFA

---

## ⚠️ Disclaimer

This is an unofficial community project. Not affiliated with or endorsed by Netwrix Corporation.
