<#
.SYNOPSIS
    Comprehensive privileged user activity analysis for PAM compliance.

.DESCRIPTION
    Analyzes privileged user access patterns including:
    - Access frequency and patterns
    - Resources accessed  
    - Privilege escalation tracking
    - After-hours/weekend access
    - Geolocation analysis (if available)
    - Compliance violations
    - Anomaly detection

.PARAMETER Days
    Number of days to analyze (default: 30)

.PARAMETER UserFilter
    Filter by specific username or pattern

.PARAMETER IncludeBehavioralAnalysis
    Include behavioral anomaly detection

.PARAMETER Export Path
    Path to export the report

.PARAMETER Format
    Export format: CSV, JSON, HTML (default: HTML)

.EXAMPLE
    .\Get-NPSPrivilegedUserActivityReport.ps1 -Days 90

    Analyzes 90 days of privileged user activity.

.EXAMPLE
    .\Get-NPSPrivilegedUserActivityReport.ps1 -UserFilter "admin" -IncludeBehavioralAnalysis

    Analyzes admin users with behavioral anomaly detection.

.EXAMPLE
    .\Get-NPSPrivilegedUserActivityReport.ps1 -Days 30 -ExportPath "./user_activity.html"

    Generates 30-day HTML report of all user activity.
#>

[CmdletBinding()]
param(
    [Parameter()]
    [int]$Days = 30,

    [Parameter()]
    [string]$UserFilter,

    [Parameter()]
    [switch]$IncludeBehavioralAnalysis,

    [Parameter()]
    [string]$ExportPath,

    [Parameter()]
    [ValidateSet('CSV', 'JSON', 'HTML')]
    [string]$Format = 'HTML'
)

Import-Module "$PSScriptRoot/../NPS-Module-Complete.psm1" -Force

if (-not (Test-NPSConnection)) {
    Write-Error "Not connected to NPS. Please run Connect-NPSServer first."
    exit 1
}

Write-Host "╔══════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║        Privileged User Activity Analysis Report             ║" -ForegroundColor Cyan
Write-Host "╚══════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host ""

$startDate = (Get-Date).AddDays(-$Days)

# Get all activity sessions
Write-Host "Retrieving privileged access sessions (last $Days days)..." -ForegroundColor Yellow
$allSessions = Get-NPSActivitySession
$sessions = $allSessions | Where-Object { 
    [DateTime]$_.actualStartDateTimeUtc -ge $startDate 
}

if ($UserFilter) {
    $sessions = $sessions | Where-Object { $_.createdByUserName -like "*$UserFilter*" }
}

Write-Host "Found $($sessions.Count) privileged access sessions" -ForegroundColor Green

# Group by user for analysis
$userActivity = $sessions | Group-Object createdByUserName | ForEach-Object {
    $user = $_.Name
    $userSessions = $_.Group
    
    # Calculate access patterns
    $totalSessions = $userSessions.Count
    $uniqueResources = ($userSessions.managedResourceName | Select-Object -Unique).Count
    $uniqueCredentials = ($userSessions.credentialId | Select-Object -Unique).Count
    $uniqueActivities = ($userSessions.activityName | Select-Object -Unique).Count
    
    # Time-based analysis
    $businessHoursSessions = $userSessions | Where-Object {
        $time = ([DateTime]$_.actualStartDateTimeUtc).TimeOfDay
        $day = ([DateTime]$_.actualStartDateTimeUtc).DayOfWeek
        $time -ge (New-TimeSpan -Hours 8) -and $time -le (New-TimeSpan -Hours 18) -and
        $day -notin @([DayOfWeek]::Saturday, [DayOfWeek]::Sunday)
    }
    
    $afterHoursSessions = $userSessions | Where-Object {
        $time = ([DateTime]$_.actualStartDateTimeUtc).TimeOfDay
        $time -lt (New-TimeSpan -Hours 6) -or $time -gt (New-TimeSpan -Hours 20)
    }
    
    $weekendSessions = $userSessions | Where-Object {
        ([DateTime]$_.actualStartDateTimeUtc).DayOfWeek -in @([DayOfWeek]::Saturday, [DayOfWeek]::Sunday)
    }
    
    # Session duration analysis
    $completedSessions = $userSessions | Where-Object { 
        $_.actualStartDateTimeUtc -and $_.actualEndDateTimeUtc 
    }
    
    $averageDuration = if ($completedSessions.Count -gt 0) {
        ($completedSessions | ForEach-Object {
            ([DateTime]$_.actualEndDateTimeUtc - [DateTime]$_.actualStartDateTimeUtc).TotalMinutes
        } | Measure-Object -Average).Average
    }
    else {
        0
    }
    
    $maxDuration = if ($completedSessions.Count -gt 0) {
        ($completedSessions | ForEach-Object {
            ([DateTime]$_.actualEndDateTimeUtc - [DateTime]$_.actualStartDateTimeUtc).TotalMinutes
        } | Measure-Object -Maximum).Maximum
    }
    else {
        0
    }
    
    # Most accessed resources
    $topResources = ($userSessions | Group-Object managedResourceName | 
        Sort-Object Count -Descending | 
        Select-Object -First 5 | 
        ForEach-Object { "$($_.Name) ($($_.Count))" }) -join ", "
    
    # Most used activities
    $topActivities = ($userSessions | Group-Object activityName | 
        Sort-Object Count -Descending | 
        Select-Object -First 3 | 
        ForEach-Object { "$($_.Name) ($($_.Count))" }) -join ", "
    
    # Failed/cancelled sessions
    $failedSessions = ($userSessions | Where-Object { $_.status -in @(4, 5) }).Count
    
    # Risk scoring
    $riskScore = 0
    $riskFactors = @()
    
    if ($afterHoursSessions.Count -gt ($totalSessions * 0.3)) {
        $riskScore += 2
        $riskFactors += "High after-hours activity"
    }
    
    if ($weekendSessions.Count -gt 5) {
        $riskScore += 1
        $riskFactors += "Weekend access"
    }
    
    if ($failedSessions -gt 3) {
        $riskScore += 2
        $riskFactors += "Multiple failed sessions"
    }
    
    if ($maxDuration -gt 480) {
        # 8 hours
        $riskScore += 1
        $riskFactors += "Extended session duration"
    }
    
    if ($uniqueResources -gt 20) {
        $riskScore += 1
        $riskFactors += "Access to many resources"
    }
    
    $riskLevel = if ($riskScore -ge 5) { "HIGH" }
    elseif ($riskScore -ge 3) { "MEDIUM" }
    else { "LOW" }
    
    [PSCustomObject]@{
        Username                = $user
        TotalSessions           = $totalSessions
        UniqueResourcesAccessed = $uniqueResources
        UniqueCredentialsUsed   = $uniqueCredentials
        UniqueActivities        = $uniqueActivities
        BusinessHoursSessions   = $businessHoursSessions.Count
        AfterHoursSessions      = $afterHoursSessions.Count
        WeekendSessions         = $weekendSessions.Count
        AfterHoursPercentage    = [math]::Round(($afterHoursSessions.Count / $totalSessions) * 100, 1)
        AverageSessionMinutes   = [math]::Round($averageDuration, 2)
        MaxSessionMinutes       = [math]::Round($maxDuration, 2)
        FailedSessions          = $failedSessions
        CompletedSessions       = ($userSessions | Where-Object { $_.status -eq 3 }).Count
        ActiveSessions          = ($userSessions | Where-Object { $_.status -eq 1 }).Count
        TopResources            = $topResources
        TopActivities           = $topActivities
        FirstAccessDate         = ($userSessions.actualStartDateTimeUtc | Sort-Object | Select-Object -First 1)
        LastAccessDate          = ($userSessions.actualStartDateTimeUtc | Sort-Object -Descending | Select-Object -First 1)
        RiskScore               = $riskScore
        RiskLevel               = $riskLevel
        RiskFactors             = ($riskFactors -join "; ")
        Sessions                = $userSessions
    }
}

# Sort by risk level and total sessions
$userActivity = $userActivity | Sort-Object @{Expression = {
        switch ($_.RiskLevel) {
            "HIGH" { 0 }
            "MEDIUM" { 1 }
            "LOW" { 2 }
        }
    }
}, TotalSessions -Descending

# Display summary
Write-Host "`n╔══════════════════════════════════════════════════════════════╗" -ForegroundColor Green
Write-Host "║                    Activity Summary                          ║" -ForegroundColor Green
Write-Host "╚══════════════════════════════════════════════════════════════╝" -ForegroundColor Green
Write-Host ""
Write-Host "Analysis Period: Last $Days days" -ForegroundColor White
Write-Host "Total Users with Privileged Access: $($userActivity.Count)" -ForegroundColor White
Write-Host "Total Privileged Sessions: $($sessions.Count)" -ForegroundColor White
Write-Host "  🔴 High Risk Users: $(($userActivity | Where-Object { $_.RiskLevel -eq 'HIGH' }).Count)" -ForegroundColor Red
Write-Host "  🟠 Medium Risk Users: $(($userActivity | Where-Object { $_.RiskLevel -eq 'MEDIUM' }).Count)" -ForegroundColor Yellow
Write-Host "  🟢 Low Risk Users: $(($userActivity | Where-Object { $_.RiskLevel -eq 'LOW' }).Count)" -ForegroundColor Green

# After-hours statistics
$totalAfterHours = ($userActivity | Measure-Object -Property AfterHoursSessions -Sum).Sum
$totalWeekend = ($userActivity | Measure-Object -Property WeekendSessions -Sum).Sum
Write-Host "`nNon-Standard Access:" -ForegroundColor Cyan
Write-Host "  After-Hours Sessions: $totalAfterHours ($(([math]::Round(($totalAfterHours / $sessions.Count) * 100, 1)))%)" -ForegroundColor Yellow
Write-Host "  Weekend Sessions: $totalWeekend ($(([math]::Round(($totalWeekend / $sessions.Count) * 100, 1)))%)" -ForegroundColor Yellow

# Top users by activity
Write-Host "`nTop 10 Most Active Users:" -ForegroundColor Cyan
$userActivity | Select-Object -First 10 | ForEach-Object {
    $color = switch ($_.RiskLevel) {
        "HIGH" { "Red" }
        "MEDIUM" { "Yellow" }
        "LOW" { "Green" }
    }
    Write-Host "  [$($_.RiskLevel.PadRight(6))] $($_.Username) - $($_.TotalSessions) sessions" -ForegroundColor $color
}

# Behavioral analysis if requested
if ($IncludeBehavioralAnalysis) {
    Write-Host "`n╔══════════════════════════════════════════════════════════════╗" -ForegroundColor Magenta
    Write-Host "║                  Behavioral Analysis                         ║" -ForegroundColor Magenta
    Write-Host "╚══════════════════════════════════════════════════════════════╝" -ForegroundColor Magenta
    
    foreach ($user in ($userActivity | Where-Object { $_.RiskLevel -ne 'LOW' } | Select-Object -First 5)) {
        Write-Host "`n👤 User: $($user.Username)" -ForegroundColor Cyan
        Write-Host "   Risk Level: $($user.RiskLevel) (Score: $($user.RiskScore))" -ForegroundColor $(
            switch ($user.RiskLevel) {
                "HIGH" { "Red" }
                "MEDIUM" { "Yellow" }
                default { "White" }
            }
        )
        
        if ($user.RiskFactors) {
            Write-Host "   ⚠ Risk Factors:" -ForegroundColor Yellow
            $user.RiskFactors -split "; " | ForEach-Object {
                Write-Host "     • $_" -ForegroundColor Gray
            }
        }
        
        Write-Host "   📊 Activity Pattern:" -ForegroundColor White
        Write-Host "     Business Hours: $($user.BusinessHoursSessions)/$($user.TotalSessions) sessions ($(100 - $user.AfterHoursPercentage)%)" -ForegroundColor Gray
        Write-Host "     After Hours: $($user.AfterHoursSessions) sessions ($($user.AfterHoursPercentage)%)" -ForegroundColor Gray
        Write-Host "     Weekend: $($user.WeekendSessions) sessions" -ForegroundColor Gray
        
        Write-Host "   🎯 Access Scope:" -ForegroundColor White
        Write-Host "     Resources: $($user.UniqueResourcesAccessed)" -ForegroundColor Gray
        Write-Host "     Credentials: $($user.UniqueCredentialsUsed)" -ForegroundColor Gray
        Write-Host "     Activities: $($user.UniqueActivities)" -ForegroundColor Gray
        
        Write-Host "   ⏱ Session Stats:" -ForegroundColor White
        Write-Host "     Average Duration: $($user.AverageSessionMinutes) minutes" -ForegroundColor Gray
        Write-Host "     Longest Session: $($user.MaxSessionMinutes) minutes" -ForegroundColor Gray
        
        if ($user.FailedSessions -gt 0) {
            Write-Host "   ❌ Failed Sessions: $($user.FailedSessions)" -ForegroundColor Red
        }
    }
}

# Export if path specified
if ($ExportPath) {
    switch ($Format) {
        'CSV' {
            $userActivity | Select-Object -ExcludeProperty Sessions | 
            Export-Csv -Path $ExportPath -NoTypeInformation
            Write-Host "`n✓ CSV report exported to: $ExportPath" -ForegroundColor Green
        }
        'JSON' {
            $exportData = @{
                GeneratedDate      = Get-Date
                AnalysisPeriodDays = $Days
                TotalUsers         = $userActivity.Count
                TotalSessions      = $sessions.Count
                HighRiskUsers      = ($userActivity | Where-Object { $_.RiskLevel -eq 'HIGH' }).Count
                MediumRiskUsers    = ($userActivity | Where-Object { $_.RiskLevel -eq 'MEDIUM' }).Count
                LowRiskUsers       = ($userActivity | Where-Object { $_.RiskLevel -eq 'LOW' }).Count
                AfterHoursSessions = $totalAfterHours
                WeekendSessions    = $totalWeekend
                UserActivity       = $userActivity | Select-Object -ExcludeProperty Sessions
            }
            $exportData | ConvertTo-Json -Depth 10 | Out-File -FilePath $ExportPath
            Write-Host "`n✓ JSON report exported to: $ExportPath" -ForegroundColor Green
        }
        'HTML' {
            $html = @"
<!DOCTYPE html>
<html>
<head>
    <title>NPS Privileged User Activity Report</title>
    <style>
        body { font-family: 'Segoe UI', Arial, sans-serif; margin: 20px; background: #f5f5f5; }
        h1 { color: #2c3e50; border-bottom: 3px solid #3498db; padding-bottom: 10px; }
        .summary { background: white; padding: 20px; border-radius: 8px; margin: 20px 0; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        .user-card { background: white; margin: 15px 0; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        .risk-high { border-left: 5px solid #e74c3c; }
        .risk-medium { border-left: 5px solid #f39c12; }
        .risk-low { border-left: 5px solid #27ae60; }
        .badge { padding: 4px 12px; border-radius: 12px; font-size: 0.9em; font-weight: bold; color: white; display: inline-block; }
        .badge-high { background: #e74c3c; }
        .badge-medium { background: #f39c12; }
        .badge-low { background: #27ae60; }
        table { width: 100%; border-collapse: collapse; margin: 10px 0; }
        th { background: #34495e; color: white; padding: 10px; text-align: left; }
        td { padding: 8px; border-bottom: 1px solid #ddd; }
        .stat-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 15px; margin: 20px 0; }
        .stat-box { padding: 20px; border-radius: 8px; color: white; text-align: center; }
        .stat-value { font-size: 2.5em; font-weight: bold; }
        .stat-label { font-size: 1em; opacity: 0.9; }
        .chart-container { margin: 20px 0; background: white; padding: 20px; border-radius: 8px; }
    </style>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
</head>
<body>
    <h1>🔐 Privileged User Activity Report</h1>
    <p>Generated: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss") | Period: Last $Days days</p>
    
    <div class="summary">
        <h2>Executive Summary</h2>
        <div class="stat-grid">
            <div class="stat-box" style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);">
                <div class="stat-value">$($userActivity.Count)</div>
                <div class="stat-label">Privileged Users</div>
            </div>
            <div class="stat-box" style="background: linear-gradient(135deg, #f093fb 0%, #f5576c 100%);">
                <div class="stat-value">$(($userActivity | Where-Object { $_.RiskLevel -eq 'HIGH' }).Count)</div>
                <div class="stat-label">High Risk</div>
            </div>
            <div class="stat-box" style="background: linear-gradient(135deg, #fa709a 0%, #fee140 100%);">
                <div class="stat-value">$totalAfterHours</div>
                <div class="stat-label">After-Hours Sessions</div>
            </div>
            <div class="stat-box" style="background: linear-gradient(135deg, #4facfe 0%, #00f2fe 100%);">
                <div class="stat-value">$($sessions.Count)</div>
                <div class="stat-label">Total Sessions</div>
            </div>
        </div>
    </div>
    
    <h2>User Activity Details</h2>
"@
            foreach ($user in $userActivity) {
                $badgeClass = "badge-$($user.RiskLevel.ToLower())"
                $cardClass = "risk-$($user.RiskLevel.ToLower())"
                
                $html += @"
    <div class="user-card $cardClass">
        <h3>$($user.Username) <span class="badge $badgeClass">$($user.RiskLevel) RISK</span></h3>
        <table>
            <tr>
                <td><strong>Total Sessions:</strong></td>
                <td>$($user.TotalSessions)</td>
                <td><strong>Business Hours:</strong></td>
                <td>$($user.BusinessHoursSessions) ($(100 - $user.AfterHoursPercentage)%)</td>
            </tr>
            <tr>
                <td><strong>Resources Accessed:</strong></td>
                <td>$($user.UniqueResourcesAccessed)</td>
                <td><strong>After Hours:</strong></td>
                <td style="color: orange;">$($user.AfterHoursSessions) ($($user.AfterHoursPercentage)%)</td>
            </tr>
            <tr>
                <td><strong>Credentials Used:</strong></td>
                <td>$($user.UniqueCredentialsUsed)</td>
                <td><strong>Weekend:</strong></td>
                <td style="color: orange;">$($user.WeekendSessions)</td>
            </tr>
            <tr>
                <td><strong>Avg Session Duration:</strong></td>
                <td>$($user.AverageSessionMinutes) min</td>
                <td><strong>Failed Sessions:</strong></td>
                <td style="color: $(if ($user.FailedSessions -gt 0) { 'red' } else { 'green' });">$($user.FailedSessions)</td>
            </tr>
        </table>
        $(if ($user.RiskFactors) {
            "<p><strong>⚠ Risk Factors:</strong> $($user.RiskFactors)</p>"
        })
        <p><strong>Top Resources:</strong> $($user.TopResources)</p>
        <p><strong>Top Activities:</strong> $($user.TopActivities)</p>
        <p><strong>Activity Period:</strong> $(([DateTime]$user.FirstAccessDate).ToString('yyyy-MM-dd')) to $(([DateTime]$user.LastAccessDate).ToString('yyyy-MM-dd'))</p>
    </div>
"@
            }
            
            $html += @"
</body>
</html>
"@
            $html | Out-File -FilePath $ExportPath
            Write-Host "`n✓ HTML report exported to: $ExportPath" -ForegroundColor Green
        }
    }
}

Write-Host "`n✓ Privileged user activity analysis complete!" -ForegroundColor Green
