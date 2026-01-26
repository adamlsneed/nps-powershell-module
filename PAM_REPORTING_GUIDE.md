# NPS PAM Reporting Suite - Complete Guide

## Overview
Enterprise-grade reporting tools for Netwrix Privilege Secure (NPS-AM) Privileged Access Management, designed for security teams, compliance officers, and IT operations.

## 📊 Available Reports

### 1. **Credential Rotation Report** (`Get-NPSCredentialRotationReport.ps1`)
**Purpose**: Track password rotation compliance and credential lifecycle

**Key Features**:
- Password rotation status with configurable thresholds
- Dormant credential detection
- Auto-rotation configuration tracking
- Credential type and platform breakdown
- Compliance rate calculation

**Usage**:
```powershell
# Basic rotation report (90-day threshold)
.\scripts\Get-NPSCredentialRotationReport.ps1

# Custom threshold with HTML output
.\scripts\Get-NPSCredentialRotationReport.ps1 -RotationThresholdDays 60 -ExportPath "./rotation.html" -Format HTML

# Include dormant credentials
.\scripts\Get-NPSCredentialRotationReport.ps1 -IncludeDormant -ShowSummary
```

**Output Metrics**:
- Total credentials analyzed
- Overdue/Due Soon/OK counts
- Dormant credentials (180+ days)
- Never-used credentials
- Compliance rate percentage
- Average rotation age

**Best For**: Monthly security reviews, audit preparation, password policy compliance

---

### 2. **Service Account Dependency Map** (`Get-NPSServiceAccountDependencyMap.ps1`)
**Purpose**: Map service account dependencies across infrastructure

**Key Features**:
- Service  account → system dependency mapping
- Windows Services and Scheduled Tasks detection
- Cross-system impact analysis
- Criticality assessment (LOW/MEDIUM/HIGH/CRITICAL)
- Password change impact prediction

**Usage**:
```powershell
# Generate interactive HTML dependency map
.\scripts\Get-NPSServiceAccountDependencyMap.ps1

# With impact analysis
.\scripts\Get-NPSServiceAccountDependencyMap.ps1 -ShowImpactAnalysis -ExportPath "./dependencies.html"

# JSON export for automation
.\scripts\Get-NPSServiceAccountDependencyMap.ps1 -Format JSON -ExportPath "./dependencies.json"
```

**Output Metrics**:
- Service accounts by criticality
- Total dependencies per account
- Direct service accounts vs. session access
- Last rotation dates
- Auto-rotation status
- Usage statistics

**Best For**: Password rotation planning, disaster recovery, change impact assessment, security incident response

---

### 3. **Privileged User Activity Report** (`Get-NPSPrivilegedUserActivityReport.ps1`)
**Purpose**: Analyze privileged user behavior and detect anomalies

**Key Features**:
- Business hours vs. after-hours analysis
- Weekend access tracking
- Resource and credential access patterns
- Session duration statistics
- Risk scoring with behavioral analysis
- Failed session tracking

**Usage**:
```powershell
# 30-day activity analysis
.\scripts\Get-NPSPrivilegedUserActivityReport.ps1 -Days 30

# With behavioral anomaly detection
.\scripts\Get-NPSPrivilegedUserActivityReport.ps1 -Days 90 -IncludeBehavioralAnalysis

# Filter specific user
.\scripts\Get-NPSPrivilegedUserActivityReport.ps1 -UserFilter "admin" -ExportPath "./admin_activity.html"
```

**Output Metrics**:
- Total sessions per user
- Business hours vs. after-hours percentage
- Weekend sessions count
- Average/max session duration
- Failed session attempts
- Risk scores (HIGH/MEDIUM/LOW)
- Resource access diversity

**Risk Factors Detected**:
- High after-hours activity (>30% of sessions)
- Weekend access patterns
- Multiple failed sessions
- Extended session durations (>8 hours)
- Access to many resources

**Best For**: Security monitoring, insider threat detection, compliance audits, user behavior analysis

---

### 4. **PAM Executive Dashboard** (`Get-NPSPAMDashboard.ps1`)
**Purpose**: Real-time comprehensive PAM health overview

**Key Features**:
- Live system health monitoring
- Key metric widgets (resources, credentials, sessions, policies)
- Compliance score calculation
- 24-hour activity summary
- Security alerts
- Top users and resources
- Credential health indicators
- Auto-refresh capability

**Usage**:
```powershell
# Static dashboard
.\scripts\Get-NPSPAMDashboard.ps1 -ExportPath "./dashboard.html"

# Auto-refreshing dashboard (updates every 5 minutes)
.\scripts\Get-NPSPAMDashboard.ps1 -ExportPath "./dashboard.html" -RefreshInterval 300
```

**Dashboard Sections**:
1. **System Overview**: Version, health, license status
2. **Key Metrics**: Resources, credentials, active sessions, policies
3. **Compliance Score**: 6-point compliance assessment
4. **24-Hour Activity**: Recent session statistics
5. **Security Alerts**: High-risk activities requiring attention
6. **Top Users**: Most active privileged users
7. **Top Resources**: Most accessed systems
8. **Credential Health**: Rotation status, auto-rotation adoption

**Compliance Checks**:
- ✓ Password rotation compliance (<10% overdue)
- ✓ Auto-rotation adoption (>70%)
- ✓ After-hours activity (<10% of sessions)
- ✓ Active access policies configured
- ✓ Session approval workflows in use
- ✓ Low failed session rate (<5 in 30 days)

**Best For**: Executive briefings, SOC dashboards, daily operations monitoring, compliance reporting

---

## 🎯 Use Case Scenarios

### Scenario 1: **Quarterly Security Review**
```powershell
# Generate comprehensive reports for quarterly review
.\scripts\Get-NPSCredentialRotationReport.ps1 -RotationThresholdDays 90 -ExportPath "./Q1_rotation.html" -Format HTML
.\scripts\Get-NPSPrivilegedUserActivityReport.ps1 -Days 90 -IncludeBehavioralAnalysis -ExportPath "./Q1_activity.html"
.\scripts\Get-NPSServiceAccountDependencyMap.ps1 -ShowImpactAnalysis -ExportPath "./Q1_dependencies.html"
```

### Scenario 2: **Audit Preparation (SOX, PCI-DSS, etc.)**
```powershell
# Generate audit-ready reports
.\scripts\Get-NPSCredentialRotationReport.ps1 -ShowSummary -ExportPath "./audit_credentials.csv" -Format CSV
.\scripts\Get-NPSPrivilegedUserActivityReport.ps1 -Days 365 -ExportPath "./audit_activity.json" -Format JSON
```

### Scenario 3: **Security Incident Investigation**
```powershell
# Investigate specific user
.\scripts\Get-NPSPrivilegedUserActivityReport.ps1 -UserFilter "suspected_user" -IncludeBehavioralAnalysis

# Check service account impacts
.\scripts\Get-NPSServiceAccountDependencyMap.ps1 -ShowImpactAnalysis
```

### Scenario 4: **Password Rotation Planning**
```powershell
# Identify accounts needing rotation and their dependencies
.\scripts\Get-NPSCredentialRotationReport.ps1 -RotationThresholdDays 60 -ShowSummary
.\scripts\Get-NPSServiceAccountDependencyMap.ps1 -ExportPath "./dependencies.html"
```

### Scenario 5: **Executive Briefing**
```powershell
# Generate executive dashboard
.\scripts\Get-NPSPAMDashboard.ps1 -ExportPath "./executive_dashboard.html"
```

---

## 📈 Report Integration Workflows

### Weekly Security Team Meeting
```powershell
# Run all reports Sunday night
$date = Get-Date -Format "yyyy-MM-dd"
.\scripts\Get-NPSPAMDashboard.ps1 -ExportPath "./weekly_dashboard_$date.html"
.\scripts\Get-NPSPrivilegedUserActivityReport.ps1 -Days 7 -ExportPath "./weekly_activity_$date.csv" -Format CSV
```

### Monthly Compliance Reporting
```powershell
# Automated monthly report generation
$month = Get-Date -Format "yyyy-MM"
.\scripts\Get-NPSCredentialRotationReport.ps1 -ExportPath "./reports/$month_rotation.html" -Format HTML -ShowSummary
.\scripts\Get-NPSPrivilegedUserActivityReport.ps1 -Days 30 -ExportPath "./reports/$month_activity.html" -Format HTML
```

### Real-Time Monitoring
```powershell
# Live dashboard for SOC
.\scripts\Get-NPSPAMDashboard.ps1 -ExportPath "C:\inetpub\wwwroot\pam\dashboard.html" -RefreshInterval 300
```

---

## 🔐 Security & Compliance Mappings

### NIST Cybersecurity Framework
- **Identify (ID)**: Credential inventory, service account dependencies
- **Protect (PR)**: Auto-rotation tracking, access policies
- **Detect (DE)**: Behavioral analysis, after-hours detection
- **Respond (RS)**: Impact analysis, security alerts

### SOX Compliance
- **Access Controls**: User activity reports, privileged access tracking
- **Change Management**: Service account dependency mapping
- **Audit Trails**: Comprehensive session logging and reporting

### PCI-DSS Requirements
- **Req 7**: Restrict access - User activity and risk analysis
- **Req 8**: Identify and authenticate - Credential rotation compliance
- **Req 10**: Track and monitor - Session activity reports

### ISO 27001
- **A.9.2.3**: Management of privileged access - All reports support this control
- **A.9.4.1**: Information access restriction - User activity analysis
- **A.12.4.1**: Event logging - Comprehensive activity tracking

---

## 📊 Recommended Reporting Schedule

| Report | Frequency | Audience | Purpose |
|--------|-----------|----------|---------|
| PAM Dashboard | Daily/Real-time | SOC, IT Ops | Operational monitoring |
| User Activity | Weekly | Security Team | Behavioral analysis |
| Credential Rotation | Monthly | Security, Compliance | Password compliance |
| Dependency Map | Quarterly | IT Ops, DR Team | Impact assessment |
| Full Audit Package | Quarterly/Annual | Auditors, Executive | Compliance evidence |

---

## 🚀 Automation Examples

### PowerShell Scheduled Task
```powershell
# Create scheduled task for daily dashboard
$action = New-ScheduledTaskAction -Execute "pwsh.exe" -Argument "-File C:\NPS\scripts\Get-NPSPAMDashboard.ps1 -ExportPath C:\Reports\daily_dashboard.html"
$trigger = New-ScheduledTaskTrigger -Daily -At "06:00AM"
Register-ScheduledTask -TaskName "NPS Daily Dashboard" -Action $action -Trigger $trigger
```

### Email Integration
```powershell
# Generate and email weekly report
$reportPath = "./weekly_report.html"
.\scripts\Get-NPSPrivilegedUserActivityReport.ps1 -Days 7 -ExportPath $reportPath -Format HTML

Send-MailMessage -From "nps@company.com" -To "security-team@company.com" `
    -Subject "Weekly PAM Activity Report - $(Get-Date -Format 'yyyy-MM-dd')" `
    -Body "See attached weekly privileged access report" `
    -Attachments $reportPath `
    -SmtpServer "smtp.company.com"
```

---

## 💡 Best Practices

### 1. **Regular Review Cadence**
- Daily: Dashboard for operational monitoring
- Weekly: User activity for security monitoring
- Monthly: Credential rotation for compliance
- Quarterly: Full audit package for executive review

### 2. **Threshold Customization**
Adjust thresholds based on your organization's risk tolerance:
```powershell
# Conservative organization (strict)
-RotationThresholdDays 30

# Standard organization
-RotationThresholdDays 90

# Relaxed environment
-RotationThresholdDays 180
```

### 3. **Export Format Selection**
- **CSV**: For Excel analysis, data warehousing
- **JSON**: For automation, SIEM integration, APIs
- **HTML**: For presentations, executive reports, dashboards

### 4. **Archival**
Maintain historical reports for trend analysis:
```powershell
$archivePath = "\\fileserver\PAM_Reports\$(Get-Date -Format 'yyyy-MM')"
New-Item -Path $archivePath -ItemType Directory -Force
.\scripts\Get-NPSPAMDashboard.ps1 -ExportPath "$archivePath\dashboard_$(Get-Date -Format 'yyyy-MM-dd').html"
```

---

## 🎨 Customization Examples

### Custom Compliance Score
Modify `Get-NPSPAMDashboard.ps1` to add organization-specific checks:
```powershell
# Add custom compliance check
if ($yourCustomCondition) {
    $complianceScore++
}
$maxScore++ # Increment max score
```

### Custom Risk Factors
Enhance `Get-NPSPrivilegedUserActivityReport.ps1` risk scoring:
```powershell
# Add custom risk factor
if ($user.CustomMetric -gt $threshold) {
    $riskScore += 2
    $riskFactors += "Custom risk detected"
}
```

---

## 📝 Report Output Examples

### Credential Rotation Report Summary
```
Total Credentials: 245
  ✗ Overdue for Rotation: 23
  ⚠ Due Soon: 45
  ✓ OK: 177
  💤 Dormant: 12
  ⊘ Never Used: 5

Rotation Compliance Rate: 72.24%
```

### User Activity Risk Analysis
```
👤 User: admin_smith
   Risk Level: HIGH (Score: 6)
   ⚠ Risk Factors:
     • High after-hours activity
     • Multiple failed sessions
     • Access to many resources
```

### Service Account Dependencies
```
🔍 Service Account: svc_backup
   Criticality: CRITICAL
   Total Dependencies: 15
   💥 Impact of Password Change:
     ⚠ Manual rotation required - High impact
     ⚠ 15 systems may experience service disruption
```

---

## 🔗 Integration with Other Tools

### Splunk Integration
```powershell
# Export for Splunk ingestion
.\scripts\Get-NPSPrivilegedUserActivityReport.ps1 -Days 1 -Format JSON -ExportPath "C:\Splunk\NPS\activity_$(Get-Date -Format 'yyyyMMdd').json"
```

### Power BI
```powershell
# Generate CSV for Power BI
.\scripts\Get-NPSCredentialRotationReport.ps1 -Format CSV -ExportPath "C:\PowerBI\NPS\credentials.csv"
```

### ServiceNow
Use JSON format for ServiceNow incident/change integration

---

## 📞 Support & Troubleshooting

### Common Issues

**Issue**: "Not connected to NPS"
```powershell
# Solution: Connect first
Connect-NPSServer -Server "https://nps.company.com:6500" -Username "user" -Password "pass" -MfaCode "123456"
```

**Issue**: Slow report generation
```powershell
# Solution: Reduce time window
-Days 30  # Instead of -Days 365
```

**Issue**: Empty reports
```powershell
# Solution: Verify data exists
Get-NPSActivitySession
Get-NPSCredential
```

---

## 📦 Complete Report Suite

All reports work together to provide comprehensive PAM visibility:

1. **Credentials** → What credentials exist and their health
2. **Dependencies** → Where credentials are used and impact
3. **Activity** → Who is using credentials and how
4. **Dashboard** → Real-time overview of all metrics

**Complete Audit Package Generation**:
```powershell
$date = Get-Date -Format "yyyy-MM-dd"
$outDir = "./PAM_Audit_$date"
New-Item -Path $outDir -ItemType Directory -Force

.\scripts\Get-NPSCredentialRotationReport.ps1 -ExportPath "$outDir/credentials.html" -Format HTML -ShowSummary
.\scripts\Get-NPSServiceAccountDependencyMap.ps1 -ExportPath "$outDir/dependencies.html" -ShowImpactAnalysis
.\scripts\Get-NPSPrivilegedUserActivityReport.ps1 -Days 90 -ExportPath "$outDir/user_activity.html" -IncludeBehavioralAnalysis
.\scripts\Get-NPSPAMDashboard.ps1 -ExportPath "$outDir/dashboard.html"

Write-Host "Complete audit package generated in: $outDir" -ForegroundColor Green
```

---

**Created**: January 25, 2026  
**Module Version**: v1.0  
**Report Suite Version**: v1.0
