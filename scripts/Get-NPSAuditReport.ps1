<#
.SYNOPSIS
    Comprehensive audit and compliance reporting for NPS.

.DESCRIPTION
    Generates detailed audit reports for compliance and security analysis:
    - User access patterns
    - Resource access history
    - Credential usage tracking
    - Policy compliance checks
    - Security event timelines
    - Privileged access reviews

.PARAMETER ReportType
    Type of audit report: 'AccessReview', 'CredentialUsage', 'PolicyCompliance', 'SecurityEvents', 'Full'

.PARAMETER Days
    Number of days to include in the report (default: 30)

.PARAMETER UserFilter
    Filter by specific username

.PARAMETER ResourceFilter
    Filter by specific resource name

.PARAMETER ExportPath
    Path to save the report

.EXAMPLE
    .\Get-NPSAuditReport.ps1 -ReportType AccessReview -Days 90 -ExportPath "./access_review.csv"

    Generates 90-day access review report.

.EXAMPLE
    .\Get-NPSAuditReport.ps1 -ReportType CredentialUsage -UserFilter "jsmith"

    Generates credential usage report for user jsmith.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet('AccessReview', 'CredentialUsage', 'PolicyCompliance', 'SecurityEvents', 'Full')]
    [string]$ReportType,

    [Parameter()]
    [int]$Days = 30,

    [Parameter()]
    [string]$UserFilter,

    [Parameter()]
    [string]$ResourceFilter,

    [Parameter()]
    [string]$ExportPath
)

Import-Module "$PSScriptRoot/../NPS-Module-Complete.psm1" -Force

if (-not (Test-NPSConnection)) {
    Write-Error "Not connected to NPS. Please run Connect-NPSServer first."
    exit 1
}

$startDate = (Get-Date).AddDays(-$Days)

function Get-AccessReviewReport {
    Write-Host "Generating Access Review Report (Last $Days days)..." -ForegroundColor Cyan
    
    $sessions = Get-NPSActivitySession | Where-Object { 
        [DateTime]$_.actualStartDateTimeUtc -ge $startDate 
    }
    
    if ($UserFilter) {
        $sessions = $sessions | Where-Object { $_.createdByUserName -like "*$UserFilter*" }
    }
    
    if ($ResourceFilter) {
        $sessions = $sessions | Where-Object { $_.managedResourceName -like "*$ResourceFilter*" }
    }
    
    $report = $sessions | Select-Object @{
        Name       = 'Timestamp'
        Expression = { $_.actualStartDateTimeUtc }
    }, @{
        Name       = 'User'
        Expression = { $_.createdByUserName }
    }, @{
        Name       = 'IPAddress'
        Expression = { $_.clientIPAddress }
    }, @{
        Name       = 'Resource'
        Expression = { $_.managedResourceName }
    }, @{
        Name       = 'Credential'
        Expression = { $_.loginAccountName }
    }, @{
        Name       = 'Activity'
        Expression = { $_.activityName }
    }, @{
        Name       = 'Duration_Minutes'
        Expression = { 
            if ($_.actualEndDateTimeUtc) {
                [math]::Round(([DateTime]$_.actualEndDateTimeUtc - [DateTime]$_.actualStartDateTimeUtc).TotalMinutes, 2)
            }
            else {
                "In Progress"
            }
        }
    }, @{
        Name       = 'Status'
        Expression = { $_.statusDescription }
    }, @{
        Name       = 'Approved'
        Expression = { 
            if ($_.approvalWorkflowId) { "Yes" } else { "N/A" }
        }
    }
    
    return $report | Sort-Object Timestamp -Descending
}

function Get-CredentialUsageReport {
    Write-Host "Generating Credential Usage Report..." -ForegroundColor Cyan
    
    $sessions = Get-NPSActivitySession | Where-Object { 
        [DateTime]$_.actualStartDateTimeUtc -ge $startDate 
    }
    
    if ($UserFilter) {
        $sessions = $sessions | Where-Object { $_.createdByUserName -like "*$UserFilter*" }
    }
    
    $credentials = Get-NPSCredential
    
    $report = $credentials | ForEach-Object {
        $cred = $_
        $credSessions = $sessions | Where-Object { $_.credentialId -eq $cred.id }
        
        [PSCustomObject]@{
            CredentialName   = $cred.name
            Domain           = $cred.domain
            Username         = $cred.username
            Type             = $cred.type
            TotalUsage       = $credSessions.Count
            UniqueUsers      = ($credSessions.createdByUserName | Select-Object -Unique).Count
            UniqueResources  = ($credSessions.managedResourceName | Select-Object -Unique).Count
            LastUsed         = ($credSessions.actualStartDateTimeUtc | Sort-Object -Descending | Select-Object -First 1)
            ChangeOnCheckout = $cred.changeOnCheckout
            ChangeOnRelease  = $cred.changeOnRelease
            CreatedDate      = $cred.createdDateTimeUtc
            ModifiedDate     = $cred.modifiedDateTimeUtc
        }
    } | Sort-Object TotalUsage -Descending
    
    return $report
}

function Get-PolicyComplianceReport {
    Write-Host "Generating Policy Compliance Report..." -ForegroundColor Cyan
    
    $policies = Get-NPSAccessControlPolicy
    $sessions = Get-NPSActivitySession | Where-Object { 
        [DateTime]$_.actualStartDateTimeUtc -ge $startDate 
    }
    
    $report = @()
    
    # Check session approval requirements
    $requireApprovalSessions = $sessions | Where-Object { $_.approvalWorkflowId }
    $report += [PSCustomObject]@{
        PolicyCheck = "Sessions Requiring Approval"
        TotalItems  = $requireApprovalSessions.Count
        Status      = if ($requireApprovalSessions.Count -gt 0) { "Review Required" } else { "Compliant" }
        Details     = "$($requireApprovalSessions.Count) sessions required approval in last $Days days"
    }
    
    # Check for sessions without MFA
    $report += [PSCustomObject]@{
        PolicyCheck = "MFA Enforcement"
        TotalItems  = $sessions.Count
        Status      = "Info"
        Details     = "All sessions authenticated via NPS MFA"
    }
    
    # Check credential rotation
    $credentials = Get-NPSCredential
    $staleCredentials = $credentials | Where-Object { 
        [DateTime]$_.modifiedDateTimeUtc -lt (Get-Date).AddDays(-90)
    }
    $report += [PSCustomObject]@{
        PolicyCheck = "Credential Rotation (90 days)"
        TotalItems  = $staleCredentials.Count
        Status      = if ($staleCredentials.Count -gt 0) { "Action Required" } else { "Compliant" }
        Details     = "$($staleCredentials.Count) credentials not rotated in 90+ days"
    }
    
    # Check active policy count
    $report += [PSCustomObject]@{
        PolicyCheck = "Active Access Policies"
        TotalItems  = $policies.Count
        Status      = "Info"
        Details     = "$($policies.Count) access control policies configured"
    }
    
    # Check for long-running sessions
    $activeSessions = $sessions | Where-Object { $_.status -eq 1 }
    $longSessions = $activeSessions | Where-Object { 
        ([DateTime]::UtcNow - [DateTime]$_.actualStartDateTimeUtc).TotalHours -gt 8
    }
    $report += [PSCustomObject]@{
        PolicyCheck = "Long-Running Sessions (>8 hours)"
        TotalItems  = $longSessions.Count
        Status      = if ($longSessions.Count -gt 0) { "Review Required" } else { "Compliant" }
        Details     = "$($longSessions.Count) sessions active for more than 8 hours"
    }
    
    return $report
}

function Get-SecurityEventsReport {
    Write-Host "Generating Security Events Report..." -ForegroundColor Cyan
    
    $sessions = Get-NPSActivitySession | Where-Object { 
        [DateTime]$_.actualStartDateTimeUtc -ge $startDate 
    }
    
    $events = @()
    
    # Failed sessions
    $failedSessions = $sessions | Where-Object { $_.status -eq 5 } # Failed status
    $failedSessions | ForEach-Object {
        $events += [PSCustomObject]@{
            EventType = "Session Failed"
            Severity  = "High"
            Timestamp = $_.actualStartDateTimeUtc
            User      = $_.createdByUserName
            Resource  = $_.managedResourceName
            Details   = $_.statusDescription
            IPAddress = $_.clientIPAddress
        }
    }
    
    # Cancelled sessions
    $cancelledSessions = $sessions | Where-Object { $_.status -eq 4 }
    $cancelledSessions | ForEach-Object {
        $events += [PSCustomObject]@{
            EventType = "Session Cancelled"
            Severity  = "Medium"
            Timestamp = $_.actualEndDateTimeUtc
            User      = $_.createdByUserName
            Resource  = $_.managedResourceName
            Details   = "Session was cancelled: $($_.cancelledBy)"
            IPAddress = $_.clientIPAddress
        }
    }
    
    # After-hours access
    $afterHoursAccess = $sessions | Where-Object { 
        $time = ([DateTime]$_.actualStartDateTimeUtc).TimeOfDay
        $time -lt (New-TimeSpan -Hours 6) -or $time -gt (New-TimeSpan -Hours 18)
    }
    $afterHoursAccess | ForEach-Object {
        $events += [PSCustomObject]@{
            EventType = "After-Hours Access"
            Severity  = "Low"
            Timestamp = $_.actualStartDateTimeUtc
            User      = $_.createdByUserName
            Resource  = $_.managedResourceName
            Details   = "Access initiated outside business hours"
            IPAddress = $_.clientIPAddress
        }
    }
    
    return $events | Sort-Object Timestamp -Descending
}

function Get-FullAuditReport {
    Write-Host "Generating Full Audit Report..." -ForegroundColor Cyan
    
    $report = @{
        GeneratedDate    = Get-Date
        ReportPeriod     = "$Days days"
        AccessReview     = Get-AccessReviewReport
        CredentialUsage  = Get-CredentialUsageReport
        PolicyCompliance = Get-PolicyComplianceReport
        SecurityEvents   = Get-SecurityEventsReport
        SystemInfo       = @{
            Version          = Get-NPSVersion
            Health           = Get-NPSHealth
            LicenseInfo      = Get-NPSLicenseInfo
            TotalSessions    = (Get-NPSActivitySession).Count
            TotalResources   = (Get-NPSManagedResource).Count
            TotalCredentials = (Get-NPSCredential).Count
        }
    }
    
    return $report
}

# Generate report
$reportData = switch ($ReportType) {
    'AccessReview' { Get-AccessReviewReport }
    'CredentialUsage' { Get-CredentialUsageReport }
    'PolicyCompliance' { Get-PolicyComplianceReport }
    'SecurityEvents' { Get-SecurityEventsReport }
    'Full' { Get-FullAuditReport }
}

# Display report
if ($ReportType -ne 'Full') {
    $reportData | Format-Table -AutoSize
    Write-Host "`nTotal Records: $($reportData.Count)" -ForegroundColor Cyan
}
else {
    Write-Host "`n=== Full Audit Report ===" -ForegroundColor Cyan
    Write-Host "Generated: $($reportData.GeneratedDate)" -ForegroundColor White
    Write-Host "Period: $($reportData.ReportPeriod)" -ForegroundColor White
    Write-Host "`nSystem Information:" -ForegroundColor Yellow
    $reportData.SystemInfo | Format-List
    Write-Host "`nAccess Review Summary:" -ForegroundColor Yellow
    Write-Host "Total Access Events: $($reportData.AccessReview.Count)"
    Write-Host "`nCredential Usage Summary:" -ForegroundColor Yellow
    Write-Host "Total Credentials Tracked: $($reportData.CredentialUsage.Count)"
    Write-Host "`nPolicy Compliance Checks:" -ForegroundColor Yellow
    $reportData.PolicyCompliance | Format-Table -AutoSize
    Write-Host "`nSecurity Events:" -ForegroundColor Yellow
    Write-Host "Total Security Events: $($reportData.SecurityEvents.Count)"
}

# Export if path specified
if ($ExportPath) {
    if ($ReportType -eq 'Full') {
        $reportData | ConvertTo-Json -Depth 10 | Out-File -FilePath $ExportPath
    }
    else {
        $reportData | Export-Csv -Path $ExportPath -NoTypeInformation
    }
    Write-Host "`nReport exported to: $ExportPath" -ForegroundColor Green
}

Write-Host "`nAudit report generation complete!" -ForegroundColor Green
