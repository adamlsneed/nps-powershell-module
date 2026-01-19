# Netwrix Privilege Secure (NPS) PowerShell Module

[![PowerShell](https://img.shields.io/badge/PowerShell-5.1%2B-blue.svg)](https://docs.microsoft.com/en-us/powershell/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

PowerShell modules for automating Netwrix Privilege Secure (formerly Stealthbits PAM) operations.

## 📁 Modules Included

| Module | Size | Functions | Description |
|--------|------|-----------|-------------|
| `NPS-Module-Complete.psm1` | 58 KB | 34 cmdlets | Custom NPS module with full Get-Help documentation |
| `SbPAMAPI-Enhanced.psm1` | 77 KB | 39 functions | Enhanced Stealthbits PAM module |

## 🚀 Quick Start

### Installation

```powershell
# Clone the repository
git clone https://github.com/adamlsneed/nps-powershell-module.git

# Import the module
Import-Module ./NPS-Module-Complete.psm1

# Or for the enhanced Stealthbits module
Import-Module ./SbPAMAPI-Enhanced.psm1
```

### Authentication

```powershell
# Connect to NPS server (requires MFA code)
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

# Get access control policies
Get-NPSAccessControlPolicy

# Check system health
Get-NPSHealth
Get-NPSVersion
```

## 📚 Available Cmdlets (NPS-Module-Complete)

### Authentication
| Cmdlet | Description |
|--------|-------------|
| `Connect-NPSServer` | Authenticate to NPS with MFA |
| `Disconnect-NPSServer` | End current session |
| `Test-NPSConnection` | Verify connection status |

### Resources & Credentials
| Cmdlet | Description |
|--------|-------------|
| `Get-NPSManagedResource` | List managed resources |
| `Search-NPSManagedResource` | Search resources with filters |
| `Get-NPSCredential` | List stored credentials |
| `Search-NPSCredential` | Search credentials |
| `Get-NPSCredentialCount` | Get credential count |

### Activities & Sessions
| Cmdlet | Description |
|--------|-------------|
| `Get-NPSActivity` | List activities |
| `Search-NPSActivity` | Search activities |
| `Get-NPSActivitySession` | List activity sessions |
| `Search-NPSActivitySession` | Search sessions |
| `Get-NPSSessionLog` | Get session logs |

### Policies & Actions
| Cmdlet | Description |
|--------|-------------|
| `Get-NPSAccessControlPolicy` | List access policies |
| `Search-NPSAccessControlPolicy` | Search policies |
| `Get-NPSActionGroup` | List action groups |
| `Get-NPSActionJob` | List action jobs |
| `Get-NPSActionQueue` | List queued actions |
| `Watch-NPSActionQueue` | Monitor action queue |

### System & Utilities
| Cmdlet | Description |
|--------|-------------|
| `Get-NPSHealth` | Check system health |
| `Get-NPSVersion` | Get NPS version |
| `Get-NPSPlatform` | List platforms |
| `Get-NPSLicenseInfo` | Get license info |
| `Invoke-NPSApi` | Low-level API wrapper |
| `Export-NPSManagedResources` | Export resources to CSV |
| `Test-NPSServices` | Test all services |

## 🔐 Authentication Flow

NPS uses a two-step MFA authentication:

1. **POST /signinBody** - Initial auth with `Login` and `Password` → Returns pre-MFA token
2. **POST /signin2fa** - MFA verification with code → Returns full JWT token

```powershell
# The Connect-NPSServer cmdlet handles this automatically
Connect-NPSServer -Server $server -Username $user -Password $pass -MfaCode $mfa
```

## 📖 Getting Help

```powershell
# Get help for any cmdlet
Get-Help Connect-NPSServer -Full
Get-Help Get-NPSManagedResource -Examples
Get-Help Get-NPSCredential -Parameter *

# List all available cmdlets
Get-Command -Module NPS-Module-Complete
```

## 🔗 Related Projects

- [NPS API Documentation](https://github.com/adamlsneed/nps-api-documentation) - Complete API reference with 55+ endpoints

## 📋 Requirements

- PowerShell 5.1 or later (PowerShell 7+ recommended)
- Network access to NPS server
- Valid NPS credentials with MFA

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## ⚠️ Disclaimer

This is an unofficial community project. Not affiliated with or endorsed by Netwrix Corporation.
