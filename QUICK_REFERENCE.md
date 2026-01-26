# NPS PowerShell Module - Quick Reference Guide

## Table of Contents
- [Installation](#installation)
- [Authentication](#authentication)
- [Common Tasks](#common-tasks)
- [Helper Scripts](#helper-scripts)
- [Troubleshooting](#troubleshooting)

## Installation

```powershell
# Clone the repository
git clone https://github.com/adamlsneed/nps-powershell-module.git
cd nps-powershell-module

# Import the module
Import-Module ./NPS-Module-Complete.psm1 -Force
```

## Authentication

### Basic Connection
```powershell
Connect-NPSServer -Server "https://your-nps-server.com:6500" `
                  -Username "domain\user" `
                  -Password "YourPassword" `
                  -MfaCode "123456" `
                  -SkipCertificateCheck
```

### Using Credentials
```powershell
$cred = Get-Credential
Connect-NPSServer -Server "https://nps.company.com:6500" `
                  -Credential $cred `
                  -MfaCode "123456"
```

### Verify Connection
```powershell
# Basic check
Test-NPSConnection

# Live API check
Test-NPSConnection -LiveCheck
```

### Disconnect
```powershell
Disconnect-NPSServer
```

## Common Tasks

### 1. View System Information
```powershell
# Get version
Get-NPSVersion

# Check health
Get-NPSHealth

# Get license information
Get-NPSLicenseInfo

# Get all platforms
Get-NPSPlatform
```

### 2. Manage Resources
```powershell
# List all resources
$resources = Get-NPSManagedResource

# Search resources (paginated)
$search = Get-NPSManagedResource -Search -First 10

# Filter resources by name
$resources | Where-Object { $_.name -like "*server*" }

# Get specific resource details
$resource = $resources | Where-Object { $_.name -eq "SERVER01" }
```

### 3. Manage Credentials
```powershell
# List all credentials
$credentials = Get-NPSCredential

# Search credentials (paginated)
$credSearch = Get-NPSCredential -Search -First 5

# Get credential types
Get-NPSCredentialTypes

# Get authentication methods
Get-NPSAuthenticationMethodTypes
```

### 4. Work with Sessions
```powershell
# List all activity sessions
$sessions = Get-NPSActivitySession

# Filter active sessions
$activeSessions = $sessions | Where-Object { $_.status -eq 1 }

# Get session count
Get-NPSActivitySessionCount

# Start a new session
$newSession = Start-NPSActivitySession `
    -ActivityName "RDP" `
    -ResourceName "SERVER01" `
    -CredentialName "Admin-SERVER01"

# Get session password
$password = Get-NPSActivitySessionPassword -Id $newSession.id

# Stop a session
Stop-NPSActivitySession -Id $session.id
```

### 5. Search and Filter
```powershell
# Search active sessions
Search-NPSActiveSession -SearchFilter "password" -Key "StdIn"

# Search historical sessions
Search-NPSHistoricalSession -SearchFilter "rm -rf"

# Filter sessions by user
$userSessions = $sessions | Where-Object { $_.createdByUserName -eq "jsmith" }

# Filter sessions by date range
$recentSessions = $sessions | Where-Object { 
    [DateTime]$_.actualStartDateTimeUtc -gt (Get-Date).AddDays(-7)
}
```

### 6. Access Policies
```powershell
# List access control policies
Get-NPSAccessControlPolicy

# Get user-specific policies
Get-NPSUserPolicy

# List domains
$resources = Get-NPSManagedResource
$domainResource = $resources | Where-Object { $_.type -eq 1 } | Select-Object -First 1
Get-NPSDomain -Id $domainResource.domainConfigId
```

### 7. Actions and Jobs
```powershell
# List action groups
Get-NPSActionGroup

# List action jobs
Get-NPSActionJob

# View action queue
Get-NPSActionQueue

# Watch action queue in real-time
Watch-NPSActionQueue
```

### 8. Export Data
```powershell
# Export resources to CSV
Get-NPSManagedResource | Export-Csv -Path "./resources.csv" -NoTypeInformation

# Export credentials
Get-NPSCredential | Export-Csv -Path "./credentials.csv" -NoTypeInformation

# Export sessions with custom fields
$sessions | Select-Object id, createdByUserName, managedResourceName, activityName, 
    actualStartDateTimeUtc, actualEndDateTimeUtc | 
    Export-Csv -Path "./sessions.csv" -NoTypeInformation
```

## Helper Scripts

### Test-NPSModule.ps1
Comprehensive test suite for all module cmdlets.

```powershell
# Run basic tests
.\scripts\Test-NPSModule.ps1

# Run with detailed output
.\scripts\Test-NPSModule.ps1 -Detailed

# Export test results
.\scripts\Test-NPSModule.ps1 -ExportResults "./test_results.json"
```

### Get-NPSSessionReport.ps1
Generate detailed session reports.

```powershell
# Active sessions report
.\scripts\Get-NPSSessionReport.ps1 -ReportType Active

# Historical sessions (last 30 days)
.\scripts\Get-NPSSessionReport.ps1 -ReportType Historical -StartDate (Get-Date).AddDays(-30) -ExportPath "./historical.csv"

# User activity report
.\scripts\Get-NPSSessionReport.ps1 -ReportType UserActivity -Format HTML -ExportPath "./user_activity.html"

# Resource usage report
.\scripts\Get-NPSSessionReport.ps1 -ReportType ResourceUsage -ExportPath "./resource_usage.csv"

# Summary report
.\scripts\Get-NPSSessionReport.ps1 -ReportType Summary
```

### Start-NPSSessionManager.ps1
Interactive session management tool.

```powershell
# Launch interactive menu
.\scripts\Start-NPSSessionManager.ps1
```

Features:
- Start new sessions (guided workflow)
- View active/all sessions
- Retrieve session passwords
- Stop sessions
- Search sessions
- View session statistics

### Get-NPSAuditReport.ps1
Compliance and security audit reports.

```powershell
# Access review report (90 days)
.\scripts\Get-NPSAuditReport.ps1 -ReportType AccessReview -Days 90 -ExportPath "./access_review.csv"

# Credential usage report
.\scripts\Get-NPSAuditReport.ps1 -ReportType CredentialUsage -ExportPath "./cred_usage.csv"

# Policy compliance check
.\scripts\Get-NPSAuditReport.ps1 -ReportType PolicyCompliance

# Security events report
.\scripts\Get-NPSAuditReport.ps1 -ReportType SecurityEvents -Days 30

# Full audit report (all sections)
.\scripts\Get-NPSAuditReport.ps1 -ReportType Full -ExportPath "./full_audit.json"

# Filter by user
.\scripts\Get-NPSAuditReport.ps1 -ReportType AccessReview -UserFilter "jsmith"

# Filter by resource
.\scripts\Get-NPSAuditReport.ps1 -ReportType AccessReview -ResourceFilter "server01"
```

### Export-NPSInventory.ps1
Export managed resources inventory.

```powershell
.\scripts\Export-NPSInventory.ps1
```

### NPS-HealthToolkit.ps1
System health and overview dashboard.

```powershell
.\scripts\NPS-HealthToolkit.ps1
```

## Troubleshooting

### Connection Issues

**Problem**: Cannot connect to NPS server
```powershell
# Solution 1: Skip certificate validation
Connect-NPSServer -Server $server -Username $user -Password $pass -MfaCode $mfa -SkipCertificateCheck

# Solution 2: Verify server URL
$server = "https://nps.company.com:6500"  # Ensure correct port

# Solution 3: Test network connectivity
Test-NetConnection -ComputerName "nps.company.com" -Port 6500
```

**Problem**: Token expired
```powershell
# Check connection
Test-NPSConnection

# Reconnect
Connect-NPSServer -Server $server -Username $user -Password $pass -MfaCode $mfa
```

### API Errors

**Problem**: 404 Not Found
```powershell
# Verify NPS version
Get-NPSVersion

# Some endpoints may not exist in older versions
# Check NPS_API_VERIFIED_REFERENCE.md for supported endpoints
```

**Problem**: 401 Unauthorized
```powershell
# Verify connection is active
Test-NPSConnection

# Reconnect if token expired
Disconnect-NPSServer
Connect-NPSServer ...
```

### Performance Optimization

**Problem**: Slow queries with large datasets
```powershell
# Use pagination
$results = Get-NPSManagedResource -Search -First 20

# Filter results early
$sessions = Get-NPSActivitySession | Where-Object { $_.status -eq 1 } | Select-Object -First 10

# Use specific queries instead of retrieving all data
$session = Get-NPSActivitySession | Where-Object { $_.id -eq $specificId }
```

### Common Errors

**Error**: "Cannot bind parameter 'Token'"
```powershell
# Ensure you're connected first
Connect-NPSServer ...

# All cmdlets now use session state automatically
Get-NPSManagedResource  # No need to pass -Token
```

**Error**: Parameter validation failed
```powershell
# MFA code must be 6 digits
Connect-NPSServer ... -MfaCode "123456"  # Correct
# Not: -MfaCode "12345" or -MfaCode "1234567"
```

## Best Practices

### 1. Session Management
```powershell
# Always verify connection before operations
if (-not (Test-NPSConnection)) {
    Connect-NPSServer ...
}

# Disconnect when done
try {
    # Your operations
    Get-NPSManagedResource
}
finally {
    Disconnect-NPSServer
}
```

### 2. Error Handling
```powershell
try {
    $resources = Get-NPSManagedResource
}
catch {
    Write-Error "Failed to retrieve resources: $_"
    # Handle error appropriately
}
```

### 3. Filtering Large Datasets
```powershell
# Use pagination for large results
$page1 = Get-NPSManagedResource -Search -First 50
$page2 = Get-NPSManagedResource -Search -Skip 50 -First 50

# Or use Where-Object efficiently
$filtered = Get-NPSManagedResource | Where-Object { 
    $_.platformName -eq "Windows" -and $_.activeSessionCount -gt 0 
}
```

### 4. Secure Credential Handling
```powershell
# Use Get-Credential for interactive scripts
$cred = Get-Credential
Connect-NPSServer -Credential $cred -MfaCode $mfa

# For automation, use secure storage
$securePassword = ConvertTo-SecureString $env:NPS_PASSWORD -AsPlainText -Force
$cred = New-Object PSCredential($env:NPS_USER, $securePassword)
```

### 5. Logging and Auditing
```powershell
# Log important operations
$session = Start-NPSActivitySession -ActivityName "RDP" -ResourceName "SERVER01" -CredentialName "Admin"
Write-Host "Session started: $($session.id) by $($session.createdByUserName)"

# Generate reports regularly
.\scripts\Get-NPSAuditReport.ps1 -ReportType Full -ExportPath "./audit_$(Get-Date -Format 'yyyy-MM-dd').json"
```

## Additional Resources

- **API Documentation**: See `NPS_API_VERIFIED_REFERENCE.md`
- **Module Source**: `NPS-Module-Complete.psm1`
- **Test Results**: `api_test_results.json`
- **GitHub**: https://github.com/adamlsneed/nps-powershell-module
