<#
.SYNOPSIS
    Executive PAM Dashboard - Comprehensive privileged access overview.

.DESCRIPTION
    Generates a comprehensive dashboard combining:
    - Overall PAM health metrics
    - Credential rotation status
    - Active privileged sessions
    - High-risk activities
    - Compliance posture
    - Security alerts
    - Trend analysis

.PARAMETER ExportPath
    Path to export HTML dashboard

.PARAMETER RefreshInterval
    Auto-refresh interval in seconds for live dashboard (0 = no refresh)

.EXAMPLE
    .\Get-NPSPAMDashboard.ps1 -ExportPath "./pam_dashboard.html"

    Generates comprehensive PAM dashboard.

.EXAMPLE
    .\Get-NPSPAMDashboard.ps1 -ExportPath "./pam_dashboard.html" -RefreshInterval 300

    Generates auto-refreshing dashboard (updates every 5 minutes).
#>

[CmdletBinding()]
param(
    [Parameter()]
    [string]$ExportPath = "./NPS_PAM_Dashboard.html",

    [Parameter()]
    [int]$RefreshInterval = 0
)

Import-Module "$PSScriptRoot/../NPS-Module-Complete.psm1" -Force

if (-not (Test-NPSConnection)) {
    Write-Error "Not connected to NPS. Please run Connect-NPSServer first."
    exit 1
}

Write-Host "╔══════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║              Generating PAM Executive Dashboard              ║" -ForegroundColor Cyan
Write-Host "╚══════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host ""

# Collect all data
Write-Host "[1/8] System health and version..." -ForegroundColor Yellow
$version = Get-NPSVersion
$health = Get-NPSHealth
$license = Get-NPSLicenseInfo

Write-Host "[2/8] Managed resources..." -ForegroundColor Yellow
$resources = Get-NPSManagedResource
$platforms = Get-NPSPlatform

Write-Host "[3/8] Credentials..." -ForegroundColor Yellow
$credentials = Get-NPSCredential

Write-Host "[4/8] Activity sessions..." -ForegroundColor Yellow
$sessions = Get-NPSActivitySession

Write-Host "[5/8] Access policies..." -ForegroundColor Yellow
$policies = Get-NPSAccessControlPolicy

Write-Host "[6/8] Action queues..." -ForegroundColor Yellow
$actionQueue = Get-NPSActionQueue

Write-Host "[7/8] Managed accounts..." -ForegroundColor Yellow
$accounts = Get-NPSManagedAccount

Write-Host "[8/8] Calculating metrics..." -ForegroundColor Yellow

# Calculate key metrics
$now = [DateTime]::UtcNow

# Resource metrics
$totalResources = $resources.Count
$activeResourceSessions = ($resources | Measure-Object -Property activeSessionCount -Sum).Sum
$resourcesByPlatform = $resources | Group-Object platformName

# Credential metrics
$totalCredentials = $credentials.Count
$serviceAccounts = ($credentials | Where-Object { $_.type -in @(1, 2) }).Count
$credentialsNeedRotation = ($credentials | Where-Object { 
        ([DateTime]::UtcNow - [DateTime]$_.modifiedDateTimeUtc).Days -gt 90 
    }).Count
$credentialsAutoRotate = ($credentials | Where-Object { $_.changeOnCheckout -or $_.changeOnRelease }).Count

# Session metrics
$activeSessions = ($sessions | Where-Object { $_.status -eq 1 }).Count
$pendingSessions = ($sessions | Where-Object { $_.status -eq 2 }).Count
$completedToday = ($sessions | Where-Object { 
        $_.status -eq 3 -and ([DateTime]$_.actualEndDateTimeUtc).Date -eq $now.Date 
    }).Count

# Last 24 hours activity
$last24Hours = $sessions | Where-Object { 
    ([DateTime]$_.actualStartDateTimeUtc) -gt $now.AddHours(-24)
}

# After-hours sessions (last 7 days)
$last7Days = $sessions | Where-Object { 
    ([DateTime]$_.actualStartDateTimeUtc) -gt $now.AddDays(-7)
}
$afterHoursSessions = $last7Days | Where-Object {
    $time = ([DateTime]$_.actualStartDateTimeUtc).TimeOfDay
    $time -lt (New-TimeSpan -Hours 6) -or $time -gt (New-TimeSpan -Hours 20)
}

# Failed sessions (last 30 days)
$last30Days = $sessions | Where-Object { 
    ([DateTime]$_.actualStartDateTimeUtc) -gt $now.AddDays(-30)
}
$failedSessions = ($last30Days | Where-Object { $_.status -in @(4, 5) }).Count

# Compliance metrics
$complianceScore = 0
$maxScore = 6

# Password rotation compliance
if ($credentialsNeedRotation -eq 0) { $complianceScore++ }
elseif ($credentialsNeedRotation -lt ($totalCredentials * 0.1)) { $complianceScore += 0.5 }

# Auto-rotation adoption
if ($credentialsAutoRotate -ge ($totalCredentials * 0.9)) { $complianceScore++ }
elseif ($credentialsAutoRotate -ge ($totalCredentials * 0.7)) { $complianceScore += 0.5 }

# After-hours activity
if ($afterHoursSessions.Count -lt ($last7Days.Count * 0.1)) { $complianceScore++ }

# Active policies
if ($policies.Count -gt 0) { $complianceScore++ }

# Session approvals
$approvalSessions = $last30Days | Where-Object { $_.approvalWorkflowId }
if ($approvalSessions.Count -gt 0) { $complianceScore++ }

# Failed sessions low
if ($failedSessions -lt 5) { $complianceScore++ }

$compliancePercentage = [math]::Round(($complianceScore / $maxScore) * 100, 1)

# Top users by sessions (last 30 days)
$topUsers = $last30Days | Group-Object createdByUserName | 
Sort-Object Count -Descending | 
Select-Object -First 5

# Top resources by sessions
$topResources = $last30Days | Group-Object managedResourceName | 
Sort-Object Count -Descending | 
Select-Object -First 5

# Recent high-risk activities
$highRiskActivities = @()

# Long-running sessions
$longSessions = $sessions | Where-Object { 
    $_.status -eq 1 -and 
    ([DateTime]::UtcNow - [DateTime]$_.actualStartDateTimeUtc).TotalHours -gt 8
}
if ($longSessions.Count -gt 0) {
    $highRiskActivities += "⚠ $($longSessions.Count) sessions running >8 hours"
}

# Multiple failed sessions by user
$failedByUser = $last30Days | Where-Object { $_.status -in @(4, 5) } | Group-Object createdByUserName |
Where-Object { $_.Count -ge 3 }
if ($failedByUser) {
    $highRiskActivities += "⚠ $($failedByUser.Count) users with multiple failed sessions"
}

# Dormant credentials
$dormantCreds = $credentials | Where-Object {
    $cred = $_
    $credSessions = $sessions | Where-Object { $_.credentialId -eq $cred.id }
    $lastUsed = if ($credSessions) { 
        $credSessions.actualStartDateTimeUtc | Sort-Object -Descending | Select-Object -First 1
    }
    if ($lastUsed) {
        ([DateTime]::UtcNow - [DateTime]$lastUsed).Days -gt 180
    }
    else {
        $true
    }
}
if ($dormantCreds.Count -gt 0) {
    $highRiskActivities += "⚠ $($dormantCreds.Count) credentials dormant >180 days"
}

# Generate HTML Dashboard
Write-Host "`nGenerating dashboard..." -ForegroundColor Green

$refreshMeta = if ($RefreshInterval -gt 0) {
    "<meta http-equiv='refresh' content='$RefreshInterval'>"
}
else {
    ""
}

$html = @"
<!DOCTYPE html>
<html>
<head>
    <title>NPS PAM Executive Dashboard</title>
    $refreshMeta
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: 'Segoe UI', -apple-system, BlinkMacSystemFont, sans-serif; background: #0f172a; color: #e2e8f0; }
        .container { max-width: 1400px; margin: 0 auto; padding: 20px; }
        header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); padding: 30px; border-radius: 12px; margin-bottom: 30px; }
        h1 { font-size: 2.5em; margin-bottom: 10px; color: white; }
        .subtitle { font-size: 1.1em; opacity: 0.9; color: white; }
        .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap: 20px; margin-bottom: 30px; }
        .card { background: #1e293b; border-radius: 12px; padding: 24px; box-shadow: 0 4px 6px rgba(0, 0, 0, 0.3); }
        .card-header { font-size: 0.9em; color: #94a3b8; text-transform: uppercase; letter-spacing: 1px; margin-bottom: 8px; }
        .card-value { font-size: 2.8em; font-weight: bold; margin-bottom: 8px; }
        .card-label { font-size: 0.95em; color: #cbd5e1; }
        .trend { font-size: 0.85em; color: #10b981; }
        .trend.down { color: #ef4444; }
        .status-good { color: #10b981; }
        .status-warning { color: #f59e0b; }
        .status-critical { color: #ef4444; }
        .chart-container { background: #1e293b; border-radius: 12px; padding: 24px; margin-bottom: 20px; }
        table { width: 100%; border-collapse: collapse; }
        th { text-align: left; padding: 12px; background: #334155; color: #f1f5f9; font-weight: 600; }
        td { padding: 12px; border-bottom: 1px solid #334155; }
        tr:hover { background: #2d3748; }
        .badge { display: inline-block; padding: 4px 12px; border-radius: 12px; font-size: 0.85em; font-weight: 600; }
        .badge-green { background: #10b981; color: white; }
        .badge-yellow { background: #f59e0b; color: white; }
        .badge-red { background: #ef4444; color: white; }
        .alert { background: #ef4444; color: white; padding: 16px; border-radius: 8px; margin-bottom: 20px; }
        .progress-bar { width: 100%; height: 24px; background: #334155; border-radius: 12px; overflow: hidden; }
        .progress-fill { height: 100%; background: linear-gradient(90deg, #10b981 0%, #059669 100%); transition: width 0.3s ease; }
        .progress-fill.warning { background: linear-gradient(90deg, #f59e0b 0%, #d97706 100%); }
        .progress-fill.critical { background: linear-gradient(90deg, #ef4444 0%, #dc2626 100%); }
        .metric-icon { font-size: 2em; margin-bottom: 10px; }
        .last-updated { text-align: right; color: #94a3b8; font-size: 0.9em; margin-top: 20px; }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>🔐 PAM Executive Dashboard</h1>
            <div class="subtitle">Comprehensive Privileged Access Management Overview</div>
            <div class="subtitle">NPS Version: $version | Health: <span class="status-good">$health</span></div>
        </header>
        
        <!-- Key Metrics -->
        <div class="grid">
            <div class="card">
                <div class="card-header">🖥️ Managed Resources</div>
                <div class="card-value">$totalResources</div>
                <div class="card-label">Across $($resourcesByPlatform.Count) platforms</div>
            </div>
            
            <div class="card">
                <div class="card-header">🔑 Total Credentials</div>
                <div class="card-value">$totalCredentials</div>
                <div class="card-label">$serviceAccounts service accounts</div>
            </div>
            
            <div class="card">
                <div class="card-header">⚡ Active Sessions</div>
                <div class="card-value class="$(if ($activeSessions -gt 10) { 'status-warning' } else { 'status-good' })">$activeSessions</div>
                <div class="card-label">$pendingSessions pending</div>
            </div>
            
            <div class="card">
                <div class="card-header">📋 Access Policies</div>
                <div class="card-value">$($policies.Count)</div>
                <div class="card-label">Active policies</div>
            </div>
        </div>
        
        <!-- Compliance Score -->
        <div class="chart-container">
            <h2 style="margin-bottom: 20px;">📊 Compliance Score</h2>
            <div style="text-align: center; margin: 20px 0;">
                <div style="font-size: 4em; font-weight: bold; class="$(
                    if ($compliancePercentage -ge 80) { 'status-good' }
                    elseif ($compliancePercentage -ge 60) { 'status-warning' }
                    else { 'status-critical' }
                )">$compliancePercentage%</div>
            </div>
            <div class="progress-bar">
                <div class="progress-fill $(
                    if ($compliancePercentage -ge 80) { '' }
                    elseif ($compliancePercentage -ge 60) { 'warning' }
                    else { 'critical' }
                )" style="width: $compliancePercentage%;"></div>
            </div>
            <div style="margin-top: 20px; display: grid; grid-template-columns: repeat(2, 1fr); gap: 15px;">
                <div>✓ Auto-rotation: $credentialsAutoRotate/$totalCredentials ($([math]::Round(($credentialsAutoRotate/$totalCredentials)*100,1))%)</div>
                <div>$(if ($credentialsNeedRotation -eq 0) { '✓' } else { '⚠' }) Rotation compliance: $(($totalCredentials - $credentialsNeedRotation))/$totalCredentials</div>
                <div>$(if ($policies.Count -gt 0) { '✓' } else { '✗' }) Access policies active</div>
                <div>$(if ($afterHoursSessions.Count -lt ($last7Days.Count * 0.2)) { '✓' } else { '⚠' }) After-hours: $($afterHoursSessions.Count)/$($last7Days.Count) sessions</div>
            </div>
        </div>
        
        <!-- Recent Activity (24h) -->
        <div class="chart-container">
            <h2 style="margin-bottom: 20px;">📈 24-Hour Activity</h2>
            <div class="grid">
                <div class="card" style="background: #334155;">
                    <div class="metric-icon">🔄</div>
                    <div class="card-value">$($last24Hours.Count)</div>
                    <div class="card-label">Total Sessions</div>
                </div>
                <div class="card" style="background: #334155;">
                    <div class="metric-icon">✅</div>
                    <div class="card-value class="status-good">$completedToday</div>
                    <div class="card-label">Completed Today</div>
                </div>
                <div class="card" style="background: #334155;">
                    <div class="metric-icon">🌙</div>
                    <div class="card-value class="status-warning">$(($last24Hours | Where-Object { 
                        $time = ([DateTime]$_.actualStartDateTimeUtc).TimeOfDay
                        $time -lt (New-TimeSpan -Hours 6) -or $time -gt (New-TimeSpan -Hours 20)
                    }).Count)</div>
                    <div class="card-label">After-Hours</div>
                </div>
            </div>
        </div>
        
        <!-- High-Risk Activities -->
        $(if ($highRiskActivities.Count -gt 0) {
            "<div class='alert'>
                <h3 style='margin-bottom: 15px;'>⚠️ Security Alerts</h3>
                <ul style='list-style: none; padding-left: 0;'>"
            ($highRiskActivities | ForEach-Object { "<li style='margin: 8px 0;'>$_</li>" }) -join ""
            "</ul></div>"
        })
        
        <!-- Top Active Users -->
        <div class="chart-container">
            <h2 style="margin-bottom: 20px;">👥 Top Active Users (30 days)</h2>
            <table>
                <thead>
                    <tr>
                        <th>User</th>
                        <th>Sessions</th>
                        <th>Status</th>
                    </tr>
                </thead>
                <tbody>
$(foreach ($user in $topUsers) {
    $badge = if ($user.Count -gt 50) { 'badge-red' } elseif ($user.Count -gt 20) { 'badge-yellow' } else { 'badge-green' }
    "                    <tr>
                        <td>$($user.Name)</td>
                        <td>$($user.Count)</td>
                        <td><span class='badge $badge'>" + $(if ($user.Count -gt 50) { 'High' } elseif ($user.Count -gt 20) { 'Medium' } else { 'Normal' }) + "</span></td>
                    </tr>"
})
                </tbody>
            </table>
        </div>
        
        <!-- Top Accessed Resources -->
        <div class="chart-container">
            <h2 style="margin-bottom: 20px;">🎯 Most Accessed Resources (30 days)</h2>
            <table>
                <thead>
                    <tr>
                        <th>Resource Name</th>
                        <th>Access Count</th>
                    </tr>
                </thead>
                <tbody>
$(foreach ($resource in $topResources) {
    "                    <tr>
                        <td>$($resource.Name)</td>
                        <td>$($resource.Count)</td>
                    </tr>"
})
                </tbody>
            </table>
        </div>
        
        <!-- Credential Status -->
        <div class="chart-container">
            <h2 style="margin-bottom: 20px;">🔑 Credential Health</h2>
            <div class="grid">
                <div class="card" style="background: #334155;">
                    <div class="card-header">Needs Rotation</div>
                    <div class="card-value class="$(if ($credentialsNeedRotation -gt 0) { 'status-warning' } else { 'status-good' })">$credentialsNeedRotation</div>
                    <div class="card-label">Over 90 days old</div>
                </div>
                <div class="card" style="background: #334155;">
                    <div class="card-header">Auto-Rotation</div>
                    <div class="card-value">$credentialsAutoRotate</div>
                    <div class="card-label">$([math]::Round(($credentialsAutoRotate/$totalCredentials)*100,1))% enabled</div>
                </div>
                <div class="card" style="background: #334155;">
                    <div class="card-header">Service Accounts</div>
                    <div class="card-value">$serviceAccounts</div>
                    <div class="card-label">Critical accounts</div>
                </div>
            </div>
        </div>
        
        <div class="last-updated">
            Last updated: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")
            $(if ($RefreshInterval -gt 0) { " | Auto-refresh: ${RefreshInterval}s" })
        </div>
    </div>
</body>
</html>
"@

$html | Out-File -FilePath $ExportPath
Write-Host "`n✓ PAM Dashboard generated: $ExportPath" -ForegroundColor Green

if ($RefreshInterval -gt 0) {
    Write-Host "  Dashboard will auto-refresh every $RefreshInterval seconds" -ForegroundColor Cyan
}

# Open in browser
if ($IsWindows -or $env:OS -eq "Windows_NT") {
    Start-Process $ExportPath
}
elseif ($IsMacOS) {
    & open $ExportPath
}
else {
    & xdg-open $ExportPath 2>/dev/null
}

Write-Host "`n✓ Dashboard complete!" -ForegroundColor Green
