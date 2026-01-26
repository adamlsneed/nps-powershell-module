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

## 📊 PAM Reporting Suite

**Enterprise-grade reports for privileged access management**, designed for security teams, compliance officers, and IT operations.

### Core PAM Reports

| Report | Purpose | Key Features |
|--------|---------|--------------|
| **Get-NPSCredentialRotationReport.ps1** | Password rotation compliance | • Rotation status tracking<br>• Dormant credential detection<br>• Compliance rate calculation |
| **Get-NPSServiceAccountDependencyMap.ps1** | Service account impact analysis | • System dependency mapping<br>• Change impact assessment<br>• Criticality scoring |
| **Get-NPSPrivilegedUserActivityReport.ps1** | User behavior analysis | • After-hours detection<br>• Risk scoring<br>• Anomaly detection |
| **Get-NPSPAMDashboard.ps1** | Executive overview dashboard | • Real-time metrics<br>• Compliance scoring<br>• Security alerts |

### Quick Examples

```powershell
# Credential rotation compliance (90-day threshold)
.\scripts\Get-NPSCredentialRotationReport.ps1 -ShowSummary

# Service account dependency map with impact analysis
.\scripts\Get-NPSServiceAccountDependencyMap.ps1 -ShowImpactAnalysis -ExportPath "./dependencies.html"

# 90-day user activity analysis with behavioral detection
.\scripts\Get-NPSPrivilegedUserActivityReport.ps1 -Days 90 -IncludeBehavioralAnalysis

# Live executive dashboard (auto-refresh every 5 minutes)
.\scripts\Get-NPSPAMDashboard.ps1 -ExportPath "./dashboard.html" -RefreshInterval 300
```

See **[PAM_REPORTING_GUIDE.md](PAM_REPORTING_GUIDE.md)** for comprehensive documentation, use cases, and compliance mappings (NIST, SOX, PCI-DSS, ISO 27001).

---

The `/scripts` directory contains powerful utilities to enhance your NPS workflows:

| Script | Description | Key Features |
|--------|-------------|--------------|
| **Test-NPSModule.ps1** | Comprehensive test suite | • Tests all 66 cmdlets<br>• Performance metrics<br>• Export results to JSON |
| **Get-NPSSessionReport.ps1** | Session reporting | • Active/Historical reports<br>• User activity analysis<br>• Export to CSV/JSON/HTML |
| **Start-NPSSessionManager.ps1** | Interactive session manager | • Menu-driven interface<br>• Start/stop sessions<br>• Password retrieval |
| **Get-NPSAuditReport.ps1** | Compliance & audit reports | • Access reviews<br>• Policy compliance<br>• Security events |
| **Export-NPSInventory.ps1** | Resource inventory export | • CSV export<br>• All resource details |
| **NPS-HealthToolkit.ps1** | Health monitoring | • System overview<br>• Quick diagnostics |

### Quick Start Examples

```powershell
# Run comprehensive tests
.\scripts\Test-NPSModule.ps1 -Detailed

# Generate session report
.\scripts\Get-NPSSessionReport.ps1 -ReportType Summary

# Launch interactive manager
.\scripts\Start-NPSSessionManager.ps1

# Compliance audit
.\scripts\Get-NPSAuditReport.ps1 -ReportType AccessReview -Days 90
```

See **[QUICK_REFERENCE.md](QUICK_REFERENCE.md)** for detailed examples and troubleshooting.

---

## 📖 Documentation

- **[QUICK_REFERENCE.md](QUICK_REFERENCE.md)** - Complete command reference and examples
- **[NPS_API_VERIFIED_REFERENCE.md](NPS_API_VERIFIED_REFERENCE.md)** - API endpoint documentation
- **Get-Help** - Built-in help for all cmdlets

```powershell
# View cmdlet help
Get-Help Connect-NPSServer -Full
Get-Help Get-NPSManagedResource -Examples

# List all available cmdlets
Get-Command -Module NPS-Module-Complete
```

---

## 📋 Requirements

- PowerShell 5.1 or later (PowerShell 7+ recommended)
- Network access to NPS server
- Valid NPS credentials with MFA

---

## ⚠️ Disclaimer

This is an unofficial community project. Not affiliated with or endorsed by Netwrix Corporation.
