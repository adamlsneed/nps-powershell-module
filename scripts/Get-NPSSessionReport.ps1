<#
.SYNOPSIS
    Generates detailed reports for NPS activity sessions.

.DESCRIPTION
    This script provides comprehensive reporting capabilities for NPS activity sessions:
    - Active sessions summary
    - Historical session analysis
    - Session duration statistics
    - Resource access patterns
    - User activity trends

.PARAMETER ReportType
    Type of report: 'Active', 'Historical', 'Summary', 'UserActivity', 'ResourceUsage'

.PARAMETER StartDate
    Start date for historical reports (default: 7 days ago)

.PARAMETER EndDate
    End date for historical reports (default: now)

.PARAMETER ExportPath
    Path to export the report (CSV, JSON, or HTML)

.PARAMETER Format
    Export format: 'CSV', 'JSON', 'HTML' (default: CSV)

.EXAMPLE
    .\Get-NPSSessionReport.ps1 -ReportType Active

    Displays current active sessions.

.EXAMPLE
    .\Get-NPSSessionReport.ps1 -ReportType Historical -StartDate (Get-Date).AddDays(-30) -ExportPath "./report.csv"

    Exports 30-day historical session report to CSV.

.EXAMPLE
    .\Get-NPSSessionReport.ps1 -ReportType UserActivity -Format HTML -ExportPath "./user_activity.html"

    Creates HTML report of user activity patterns.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet('Active', 'Historical', 'Summary', 'UserActivity', 'ResourceUsage')]
    [string]$ReportType,

    [Parameter()]
    [DateTime]$StartDate = (Get-Date).AddDays(-7),

    [Parameter()]
    [DateTime]$EndDate = (Get-Date),

    [Parameter()]
    [string]$ExportPath,

    [Parameter()]
    [ValidateSet('CSV', 'JSON', 'HTML')]
    [string]$Format = 'CSV'
)

Import-Module "$PSScriptRoot/../NPS-Module-Complete.psm1" -Force

# Verify connection
if (-not (Test-NPSConnection)) {
    Write-Error "Not connected to NPS. Please run Connect-NPSServer first."
    exit 1
}

function Get-ActiveSessionsReport {
    Write-Host "Generating Active Sessions Report..." -ForegroundColor Cyan
    
    $sessions = Get-NPSActivitySession
    $activeSessions = $sessions | Where-Object { $_.status -in @(1, 2) } # Active or Pending
    
    $report = $activeSessions | Select-Object @{
        Name       = 'SessionID'
        Expression = { $_.id }
    }, @{
        Name       = 'User'
        Expression = { $_.createdByUserName }
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
        Name       = 'Status'
        Expression = { $_.statusDescription }
    }, @{
        Name       = 'StartTime'
        Expression = { $_.actualStartDateTimeUtc }
    }, @{
        Name       = 'ScheduledEnd'
        Expression = { $_.scheduledEndDateTimeUtc }
    }, @{
        Name       = 'Duration'
        Expression = { 
            if ($_.actualStartDateTimeUtc) {
                (Get-Date) - [DateTime]$_.actualStartDateTimeUtc
            }
        }
    }
    
    return $report
}

function Get-HistoricalSessionsReport {
    Write-Host "Generating Historical Sessions Report ($StartDate to $EndDate)..." -ForegroundColor Cyan
    
    $sessions = Get-NPSActivitySession
    $historicalSessions = $sessions | Where-Object { 
        [DateTime]$_.actualStartDateTimeUtc -ge $StartDate -and 
        [DateTime]$_.actualStartDateTimeUtc -le $EndDate
    }
    
    $report = $historicalSessions | Select-Object @{
        Name       = 'SessionID'
        Expression = { $_.id }
    }, @{
        Name       = 'User'
        Expression = { $_.createdByUserName }
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
        Name       = 'Status'
        Expression = { $_.statusDescription }
    }, @{
        Name       = 'StartTime'
        Expression = { $_.actualStartDateTimeUtc }
    }, @{
        Name       = 'EndTime'
        Expression = { $_.actualEndDateTimeUtc }
    }, @{
        Name       = 'DurationMinutes'
        Expression = { 
            if ($_.actualStartDateTimeUtc -and $_.actualEndDateTimeUtc) {
                ([DateTime]$_.actualEndDateTimeUtc - [DateTime]$_.actualStartDateTimeUtc).TotalMinutes
            }
        }
    }
    
    return $report
}

function Get-SessionSummaryReport {
    Write-Host "Generating Session Summary Report..." -ForegroundColor Cyan
    
    $sessions = Get-NPSActivitySession
    
    $summary = [PSCustomObject]@{
        TotalSessions      = $sessions.Count
        ActiveSessions     = ($sessions | Where-Object { $_.status -eq 1 }).Count
        PendingSessions    = ($sessions | Where-Object { $_.status -eq 2 }).Count
        CompletedSessions  = ($sessions | Where-Object { $_.status -eq 3 }).Count
        CancelledSessions  = ($sessions | Where-Object { $_.status -eq 4 }).Count
        UniqueUsers        = ($sessions.createdByUserName | Select-Object -Unique).Count
        UniqueResources    = ($sessions.managedResourceName | Select-Object -Unique).Count
        TopActivity        = ($sessions | Group-Object activityName | Sort-Object Count -Descending | Select-Object -First 1).Name
        TopUser            = ($sessions | Group-Object createdByUserName | Sort-Object Count -Descending | Select-Object -First 1).Name
        TopResource        = ($sessions | Group-Object managedResourceName | Sort-Object Count -Descending | Select-Object -First 1).Name
        AverageSessionTime = [math]::Round((
                $sessions | Where-Object { $_.actualStartDateTimeUtc -and $_.actualEndDateTimeUtc } | 
                ForEach-Object { ([DateTime]$_.actualEndDateTimeUtc - [DateTime]$_.actualStartDateTimeUtc).TotalMinutes } |
                Measure-Object -Average
            ).Average, 2)
    }
    
    return $summary
}

function Get-UserActivityReport {
    Write-Host "Generating User Activity Report..." -ForegroundColor Cyan
    
    $sessions = Get-NPSActivitySession | Where-Object { 
        [DateTime]$_.actualStartDateTimeUtc -ge $StartDate -and 
        [DateTime]$_.actualStartDateTimeUtc -le $EndDate
    }
    
    $report = $sessions | Group-Object createdByUserName | ForEach-Object {
        [PSCustomObject]@{
            Username           = $_.Name
            TotalSessions      = $_.Count
            ActiveSessions     = ($_.Group | Where-Object { $_.status -in @(1, 2) }).Count
            CompletedSessions  = ($_.Group | Where-Object { $_.status -eq 3 }).Count
            CancelledSessions  = ($_.Group | Where-Object { $_.status -eq 4 }).Count
            UniqueResources    = ($_.Group.managedResourceName | Select-Object -Unique).Count
            MostUsedActivity   = ($_.Group | Group-Object activityName | Sort-Object Count -Descending | Select-Object -First 1).Name
            AverageSessionTime = [math]::Round((
                    $_.Group | Where-Object { $_.actualStartDateTimeUtc -and $_.actualEndDateTimeUtc } | 
                    ForEach-Object { ([DateTime]$_.actualEndDateTimeUtc - [DateTime]$_.actualStartDateTimeUtc).TotalMinutes } |
                    Measure-Object -Average
                ).Average, 2)
            LastActivity       = ($_.Group.actualStartDateTimeUtc | Sort-Object -Descending | Select-Object -First 1)
        }
    } | Sort-Object TotalSessions -Descending
    
    return $report
}

function Get-ResourceUsageReport {
    Write-Host "Generating Resource Usage Report..." -ForegroundColor Cyan
    
    $sessions = Get-NPSActivitySession | Where-Object { 
        [DateTime]$_.actualStartDateTimeUtc -ge $StartDate -and 
        [DateTime]$_.actualStartDateTimeUtc -le $EndDate
    }
    
    $report = $sessions | Group-Object managedResourceName | ForEach-Object {
        [PSCustomObject]@{
            ResourceName       = $_.Name
            TotalSessions      = $_.Count
            UniqueUsers        = ($_.Group.createdByUserName | Select-Object -Unique).Count
            MostUsedActivity   = ($_.Group | Group-Object activityName | Sort-Object Count -Descending | Select-Object -First 1).Name
            AverageSessionTime = [math]::Round((
                    $_.Group | Where-Object { $_.actualStartDateTimeUtc -and $_.actualEndDateTimeUtc } | 
                    ForEach-Object { ([DateTime]$_.actualEndDateTimeUtc - [DateTime]$_.actualStartDateTimeUtc).TotalMinutes } |
                    Measure-Object -Average
                ).Average, 2)
            LastAccessed       = ($_.Group.actualStartDateTimeUtc | Sort-Object -Descending | Select-Object -First 1)
        }
    } | Sort-Object TotalSessions -Descending
    
    return $report
}

# Generate report based on type
$reportData = switch ($ReportType) {
    'Active' { Get-ActiveSessionsReport }
    'Historical' { Get-HistoricalSessionsReport }
    'Summary' { Get-SessionSummaryReport }
    'UserActivity' { Get-UserActivityReport }
    'ResourceUsage' { Get-ResourceUsageReport }
}

# Display report
$reportData | Format-Table -AutoSize

# Export if path specified
if ($ExportPath) {
    switch ($Format) {
        'CSV' {
            $reportData | Export-Csv -Path $ExportPath -NoTypeInformation
            Write-Host "`nReport exported to: $ExportPath" -ForegroundColor Green
        }
        'JSON' {
            $reportData | ConvertTo-Json -Depth 10 | Out-File -FilePath $ExportPath
            Write-Host "`nReport exported to: $ExportPath" -ForegroundColor Green
        }
        'HTML' {
            $html = @"
<!DOCTYPE html>
<html>
<head>
    <title>NPS Session Report - $ReportType</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        h1 { color: #333; }
        table { border-collapse: collapse; width: 100%; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        th { background-color: #4CAF50; color: white; }
        tr:nth-child(even) { background-color: #f2f2f2; }
    </style>
</head>
<body>
    <h1>NPS Session Report - $ReportType</h1>
    <p>Generated: $(Get-Date)</p>
    $(if ($StartDate -and $EndDate) { "<p>Period: $StartDate to $EndDate</p>" })
    $($reportData | ConvertTo-Html -Fragment)
</body>
</html>
"@
            $html | Out-File -FilePath $ExportPath
            Write-Host "`nReport exported to: $ExportPath" -ForegroundColor Green
        }
    }
}

Write-Host "`nReport generation complete!" -ForegroundColor Green
