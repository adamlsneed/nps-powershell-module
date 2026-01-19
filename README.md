# Netwrix Privilege Secure (NPS) PowerShell Module

[![PowerShell](https://img.shields.io/badge/PowerShell-5.1%2B-blue.svg)](https://docs.microsoft.com/en-us/powershell/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

Comprehensive PowerShell modules and documentation for automating Netwrix Privilege Secure (formerly Stealthbits PAM) API operations.

## 📁 Repository Structure

```
├── modules/
│   ├── NPS-Module-Complete.psm1    # Full NPS module (34 cmdlets)
│   └── SbPAMAPI-Enhanced.psm1      # Enhanced Stealthbits module (39 functions)
├── docs/
│   ├── NPS_MASTER_DOCUMENTATION.md # Complete API documentation
│   ├── NPS_API_Complete_Reference.md
│   ├── NPS_MODULE_TEST_REPORT.md
│   └── SbPAM-QuickReference.md
└── README.md
```

## 🚀 Quick Start

### Installation

```powershell
# Import the module
Import-Module ./modules/NPS-Module-Complete.psm1

# Or for the enhanced Stealthbits module
Import-Module ./modules/SbPAMAPI-Enhanced.psm1
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

| Category | Cmdlets |
|----------|--------|
| **Authentication** | `Connect-NPSServer`, `Disconnect-NPSServer`, `Test-NPSConnection` |
| **Resources** | `Get-NPSManagedResource`, `Search-NPSManagedResource` |
| **Credentials** | `Get-NPSCredential`, `Search-NPSCredential`, `Get-NPSCredentialCount` |
| **Activities** | `Get-NPSActivity`, `Search-NPSActivity`, `Get-NPSActivitySession` |
| **Policies** | `Get-NPSAccessControlPolicy`, `Search-NPSAccessControlPolicy` |
| **Actions** | `Get-NPSActionGroup`, `Get-NPSActionJob`, `Get-NPSActionQueue` |
| **Scanning** | `Get-NPSHostScanJob`, `Search-NPSHostScanJob` |
| **System** | `Get-NPSHealth`, `Get-NPSVersion`, `Get-NPSPlatform`, `Get-NPSLicenseInfo` |
| **Utilities** | `Invoke-NPSApi`, `Export-NPSManagedResources`, `Watch-NPSActionQueue` |

## 🔐 Authentication Flow

NPS uses a two-step MFA authentication:

1. **POST /signinBody** - Initial auth with `Login` and `Password` → Returns pre-MFA token
2. **POST /signin2fa** - MFA verification with code → Returns full JWT token

```powershell
# The Connect-NPSServer cmdlet handles this automatically
Connect-NPSServer -Server $server -Username $user -Password $pass -MfaCode $mfa
```

## 📖 Documentation

- [Master Documentation](docs/NPS_MASTER_DOCUMENTATION.md) - Complete API reference with 55+ endpoints
- [API Reference](docs/NPS_API_Complete_Reference.md) - Detailed endpoint documentation
- [Test Report](docs/NPS_MODULE_TEST_REPORT.md) - Module testing results
- [Quick Reference](docs/SbPAM-QuickReference.md) - Function quick reference

## 🔧 API Endpoints Discovered

| Category | Endpoints | Records Found |
|----------|-----------|---------------|
| ManagedResource | 3 | 1,200+ |
| Credential | 3 | 661 |
| Activity | 2 | 100+ |
| ActivitySession | 3 | 50+ |
| AccessControlPolicy | 2 | 10+ |
| ActionJob | 2 | 6,500+ |
| HostScanJob | 2 | 110+ |
| Platform | 1 | 15 |
| System (Health/Version) | 3 | - |

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
