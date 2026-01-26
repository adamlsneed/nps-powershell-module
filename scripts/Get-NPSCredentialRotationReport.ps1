<#
.SYNOPSIS
    Comprehensive credential rotation and lifecycle report for PAM compliance.

.DESCRIPTION
    Generates detailed reports on credential lifecycle including:
    - Last password rotation dates
    - Credentials requiring rotation (configurable age threshold)
    - Credential types and platform assignments
    - Change-on-checkout/release settings
    - Unused or dormant credentials
    - Service account tracking

.PARAMETER RotationThresholdDays
    Number of days after which a credential is considered due for rotation (default: 90)

.PARAMETER IncludeDormant
    Include credentials that haven't been used in specified period (default: 180 days)

.PARAMETER ExportPath
    Path to export the report (CSV, JSON, or HTML)

.PARAMETER Format
    Export format: CSV, JSON, HTML (default: CSV)

.PARAMETER ShowSummary
    Display summary statistics

.EXAMPLE
    .\Get-NPSCredentialRotationReport.ps1

    Displays credential rotation status with 90-day threshold.

.EXAMPLE
    .\Get-NPSCredentialRotationReport.ps1 -RotationThresholdDays 60 -ExportPath "./rotation_report.html" -Format HTML

    Generates HTML report with 60-day rotation threshold.

.EXAMPLE
    .\Get-NPSCredentialRotationReport.ps1 -IncludeDormant -ShowSummary

    Shows full report including dormant credentials with summary stats.
#>

[CmdletBinding()]
param(
    [Parameter()]
    [int]$RotationThresholdDays = 90,

    [Parameter()]
    [switch]$IncludeDormant,

    [Parameter()]
    [int]$DormantThresholdDays = 180,

    [Parameter()]
    [string]$ExportPath,

    [Parameter()]
    [ValidateSet('CSV', 'JSON', 'HTML')]
    [string]$Format = 'CSV',

    [Parameter()]
    [switch]$ShowSummary
)

Import-Module "$PSScriptRoot/../NPS-Module-Complete.psm1" -Force

if (-not (Test-NPSConnection)) {
    Write-Error "Not connected to NPS. Please run Connect-NPSServer first."
    exit 1
}

Write-Host "╔══════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║        NPS Credential Rotation & Lifecycle Report           ║" -ForegroundColor Cyan
Write-Host "╚══════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host ""

# Get all credentials
Write-Host "Retrieving credentials..." -ForegroundColor Yellow
$credentials = Get-NPSCredential

# Get activity sessions for usage tracking
Write-Host "Analyzing credential usage..." -ForegroundColor Yellow
$sessions = Get-NPSActivitySession

# Get platforms for mapping
$platforms = Get-NPSPlatform

# Build comprehensive credential report
$report = $credentials | ForEach-Object {
    $cred = $_
    $platform = $platforms | Where-Object { $_.id -eq $cred.platformId } | Select-Object -First 1
    
    # Calculate days since last rotation
    $lastRotation = [DateTime]$cred.modifiedDateTimeUtc
    $daysSinceRotation = ([DateTime]::UtcNow - $lastRotation).Days
    
    # Get usage information
    $credSessions = $sessions | Where-Object { $_.credentialId -eq $cred.id }
    $lastUsed = if ($credSessions) {
        ($credSessions.actualStartDateTimeUtc | Sort-Object -Descending | Select-Object -First 1)
    }
    else {
        $null
    }
    
    $daysSinceLastUse = if ($lastUsed) {
        ([DateTime]::UtcNow - [DateTime]$lastUsed).Days
    }
    else {
        $null
    }
    
    # Determine credential type
    $credentialType = switch ($cred.type) {
        0 { "User" }
        1 { "Service" }
        2 { "Application" }
        3 { "Configuration" }
        4 { "ActivityToken" }
        5 { "VaultUser" }
        6 { "SshKeyCert" }
        default { "Unknown" }
    }
    
    # Determine rotation status
    $rotationStatus = if ($daysSinceRotation -gt $RotationThresholdDays) {
        "OVERDUE"
    }
    elseif ($daysSinceRotation -gt ($RotationThresholdDays * 0.8)) {
        "DUE SOON"
    }
    else {
        "OK"
    }
    
    # Check if dormant
    $isDormant = if ($daysSinceLastUse -and $daysSinceLastUse -gt $DormantThresholdDays) {
        "Yes"
    }
    else {
        "No"
    }
    
    [PSCustomObject]@{
        CredentialName       = $cred.name
        Domain               = $cred.domain
        Username             = $cred.username
        Type                 = $credentialType
        Platform             = $platform.name
        LastRotationDate     = $lastRotation.ToString("yyyy-MM-dd HH:mm")
        DaysSinceRotation    = $daysSinceRotation
        RotationStatus       = $rotationStatus
        ChangeOnCheckout     = $cred.changeOnCheckout
        ChangeOnRelease      = $cred.changeOnRelease
        LastUsedDate         = if ($lastUsed) { ([DateTime]$lastUsed).ToString("yyyy-MM-dd HH:mm") } else { "Never" }
        DaysSinceLastUse     = $daysSinceLastUse
        IsDormant            = $isDormant
        TotalUsageCount      = $credSessions.Count
        AuthenticationMethod = switch ($cred.authenticationMethod) {
            0 { "Password" }
            1 { "SshCertificate" }
            2 { "SshCertAndPassword" }
            default { "Unknown" }
        }
        CreatedDate          = ([DateTime]$cred.createdDateTimeUtc).ToString("yyyy-MM-dd")
        IsDeleted            = $cred.isDeleted
        CredentialId         = $cred.id
    }
}

# Filter for dormant if requested
if (-not $IncludeDormant) {
    $report = $report | Where-Object { $_.IsDormant -eq "No" }
}

# Sort by rotation status and days since rotation
$report = $report | Sort-Object @{Expression = {
        switch ($_.RotationStatus) {
            "OVERDUE" { 0 }
            "DUE SOON" { 1 }
            "OK" { 2 }
        }
    }
}, DaysSinceRotation -Descending

# Display report
Write-Host "`nCredential Rotation Report:" -ForegroundColor Cyan
$report | Format-Table -AutoSize

# Calculate and display summary statistics
if ($ShowSummary -or (-not $ExportPath)) {
    Write-Host "`n╔══════════════════════════════════════════════════════════════╗" -ForegroundColor Green
    Write-Host "║                    Summary Statistics                        ║" -ForegroundColor Green
    Write-Host "╚══════════════════════════════════════════════════════════════╝" -ForegroundColor Green
    
    $totalCredentials = $report.Count
    $overdueCredentials = ($report | Where-Object { $_.RotationStatus -eq "OVERDUE" }).Count
    $dueSoonCredentials = ($report | Where-Object { $_.RotationStatus -eq "DUE SOON" }).Count
    $okCredentials = ($report | Where-Object { $_.RotationStatus -eq "OK" }).Count
    $dormantCredentials = ($report | Where-Object { $_.IsDormant -eq "Yes" }).Count
    $neverUsedCredentials = ($report | Where-Object { $_.LastUsedDate -eq "Never" }).Count
    
    # Group by type
    $byType = $report | Group-Object Type
    
    # Group by platform
    $byPlatform = $report | Group-Object Platform
    
    Write-Host ""
    Write-Host "Total Credentials: $totalCredentials" -ForegroundColor White
    Write-Host "  ✗ Overdue for Rotation: $overdueCredentials" -ForegroundColor Red
    Write-Host "  ⚠ Due Soon: $dueSoonCredentials" -ForegroundColor Yellow
    Write-Host "  ✓ OK: $okCredentials" -ForegroundColor Green
    Write-Host "  💤 Dormant: $dormantCredentials" -ForegroundColor DarkGray
    Write-Host "  ⊘ Never Used: $neverUsedCredentials" -ForegroundColor DarkYellow
    
    Write-Host "`nBy Credential Type:" -ForegroundColor Cyan
    $byType | ForEach-Object {
        Write-Host "  $($_.Name): $($_.Count)"
    }
    
    Write-Host "`nBy Platform:" -ForegroundColor Cyan
    $byPlatform | Sort-Object Count -Descending | Select-Object -First 10 | ForEach-Object {
        Write-Host "  $($_.Name): $($_.Count)"
    }
    
    Write-Host "`nRotation Compliance Rate: $([math]::Round(($okCredentials / $totalCredentials) * 100, 2))%" -ForegroundColor $(
        if (($okCredentials / $totalCredentials) -ge 0.9) { "Green" }
        elseif (($okCredentials / $totalCredentials) -ge 0.7) { "Yellow" }
        else { "Red" }
    )
    
    # Average rotation age
    $avgRotationAge = ($report.DaysSinceRotation | Measure-Object -Average).Average
    Write-Host "Average Days Since Rotation: $([math]::Round($avgRotationAge, 0))" -ForegroundColor White
    
    # Credentials with auto-rotation disabled
    $noAutoRotate = ($report | Where-Object { -not $_.ChangeOnCheckout -and -not $_.ChangeOnRelease }).Count
    Write-Host "Credentials Without Auto-Rotation: $noAutoRotate" -ForegroundColor $(if ($noAutoRotate -gt 0) { "Yellow" } else { "Green" })
}

# Export if path specified
if ($ExportPath) {
    switch ($Format) {
        'CSV' {
            $report | Export-Csv -Path $ExportPath -NoTypeInformation
            Write-Host "`n✓ Report exported to: $ExportPath" -ForegroundColor Green
        }
        'JSON' {
            $exportData = @{
                GeneratedDate     = Get-Date
                RotationThreshold = $RotationThresholdDays
                DormantThreshold  = $DormantThresholdDays
                TotalCredentials  = $totalCredentials
                OverdueCount      = $overdueCredentials
                DueSoonCount      = $dueSoonCredentials
                OkCount           = $okCredentials
                DormantCount      = $dormantCredentials
                ComplianceRate    = [math]::Round(($okCredentials / $totalCredentials) * 100, 2)
                Credentials       = $report
            }
            $exportData | ConvertTo-Json -Depth 10 | Out-File -FilePath $ExportPath
            Write-Host "`n✓ Report exported to: $ExportPath" -ForegroundColor Green
        }
        'HTML' {
            $html = @"
<!DOCTYPE html>
<html>
<head>
    <title>NPS Credential Rotation Report</title>
    <style>
        body { font-family: 'Segoe UI', Arial, sans-serif; margin: 20px; background: #f5f5f5; }
        h1 { color: #2c3e50; border-bottom: 3px solid #3498db; padding-bottom: 10px; }
        .summary { background: white; padding: 20px; border-radius: 8px; margin: 20px 0; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        .stat { display: inline-block; margin: 10px 20px; }
        .stat-value { font-size: 2em; font-weight: bold; }
        .overdue { color: #e74c3c; }
        .due-soon { color: #f39c12; }
        .ok { color: #27ae60; }
        table { border-collapse: collapse; width: 100%; background: white; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        th { background-color: #34495e; color: white; padding: 12px; text-align: left; }
        td { border: 1px solid #ddd; padding: 10px; }
        tr:nth-child(even) { background-color: #f9f9f9; }
        tr:hover { background-color: #f1f1f1; }
        .status-overdue { color: white; background-color: #e74c3c; padding: 4px 8px; border-radius: 4px; font-weight: bold; }
        .status-due-soon { color: white; background-color: #f39c12; padding: 4px 8px; border-radius: 4px; font-weight: bold; }
        .status-ok { color: white; background-color: #27ae60; padding: 4px 8px; border-radius: 4px; font-weight: bold; }
    </style>
</head>
<body>
    <h1>🔐 NPS Credential Rotation Report</h1>
    <p>Generated: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")</p>
    <p>Rotation Threshold: $RotationThresholdDays days | Dormant Threshold: $DormantThresholdDays days</p>
    
    <div class="summary">
        <h2>Summary Statistics</h2>
        <div class="stat">
            <div>Total Credentials</div>
            <div class="stat-value">$totalCredentials</div>
        </div>
        <div class="stat overdue">
            <div>Overdue</div>
            <div class="stat-value">$overdueCredentials</div>
        </div>
        <div class="stat due-soon">
            <div>Due Soon</div>
            <div class="stat-value">$dueSoonCredentials</div>
        </div>
        <div class="stat ok">
            <div>OK</div>
            <div class="stat-value">$okCredentials</div>
        </div>
        <div class="stat">
            <div>Compliance Rate</div>
            <div class="stat-value">$([math]::Round(($okCredentials / $totalCredentials) * 100, 1))%</div>
        </div>
    </div>
    
    <h2>Credential Details</h2>
    <table>
        <thead>
            <tr>
                <th>Credential Name</th>
                <th>Type</th>
                <th>Platform</th>
                <th>Last Rotation</th>
                <th>Days Since</th>
                <th>Status</th>
                <th>Last Used</th>
                <th>Usage Count</th>
                <th>Auto-Rotate</th>
            </tr>
        </thead>
        <tbody>
"@
            $report | ForEach-Object {
                $statusClass = switch ($_.RotationStatus) {
                    "OVERDUE" { "status-overdue" }
                    "DUE SOON" { "status-due-soon" }
                    "OK" { "status-ok" }
                }
                $autoRotate = if ($_.ChangeOnCheckout -or $_.ChangeOnRelease) { "✓" } else { "✗" }
                
                $html += @"
            <tr>
                <td>$($_.CredentialName)</td>
                <td>$($_.Type)</td>
                <td>$($_.Platform)</td>
                <td>$($_.LastRotationDate)</td>
                <td>$($_.DaysSinceRotation)</td>
                <td><span class="$statusClass">$($_.RotationStatus)</span></td>
                <td>$($_.LastUsedDate)</td>
                <td>$($_.TotalUsageCount)</td>
                <td>$autoRotate</td>
            </tr>
"@
            }
            
            $html += @"
        </tbody>
    </table>
</body>
</html>
"@
            $html | Out-File -FilePath $ExportPath
            Write-Host "`n✓ HTML report exported to: $ExportPath" -ForegroundColor Green
        }
    }
}

Write-Host "`n✓ Credential rotation report complete!" -ForegroundColor Green
