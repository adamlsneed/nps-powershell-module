<#
.SYNOPSIS
    Service account dependency mapping report for critical infrastructure protection.

.DESCRIPTION
    Maps service accounts to their dependencies including:
    - Windows Services using the account
    - Scheduled Tasks using the account
    - Application dependencies
    - Resources where the account is used
    - Cross-system impact analysis
    
    Critical for:
    - Change impact assessment
    - Password rotation planning
    - Disaster recovery planning
    - Security incident response

.PARAMETER IncludeInactive
    Include disabled services and tasks in the report

.PARAMETER ExportPath
    Path to export the dependency map

.PARAMETER Format
    Export format: CSV, JSON, HTML, Graph (default: HTML)

.PARAMETER ShowImpactAnalysis
    Display impact analysis for each service account

.EXAMPLE
    .\Get-NPSServiceAccountDependencyMap.ps1

    Generates interactive HTML dependency map.

.EXAMPLE
    .\Get-NPSServiceAccountDependencyMap.ps1 -ShowImpactAnalysis -ExportPath "./dependencies.html"

    Creates detailed HTML report with impact analysis.

.EXAMPLE
    .\Get-NPSServiceAccountDependencyMap.ps1 -Format JSON -ExportPath "./dependencies.json"

    Exports raw dependency data in JSON format.
#>

[CmdletBinding()]
param(
    [Parameter()]
    [switch]$IncludeInactive,

    [Parameter()]
    [string]$ExportPath,

    [Parameter()]
    [ValidateSet('CSV', 'JSON', 'HTML', 'Graph')]
    [string]$Format = 'HTML',

    [Parameter()]
    [switch]$ShowImpactAnalysis
)

Import-Module "$PSScriptRoot/../NPS-Module-Complete.psm1" -Force

if (-not (Test-NPSConnection)) {
    Write-Error "Not connected to NPS. Please run Connect-NPSServer first."
    exit 1
}

Write-Host "╔══════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║      NPS Service Account Dependency Mapping Report          ║" -ForegroundColor Cyan
Write-Host "╚══════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host ""

# Get all credentials (focus on service accounts)
Write-Host "Retrieving service accounts..." -ForegroundColor Yellow
$credentials = Get-NPSCredential
$serviceAccounts = $credentials | Where-Object { $_.type -in @(1, 2) } # Service and Application types

Write-Host "Found $($serviceAccounts.Count) service accounts" -ForegroundColor Green

# Get all managed resources
Write-Host "Retrieving managed resources..." -ForegroundColor Yellow
$resources = Get-NPSManagedResource

# Get activity sessions to understand where accounts are used
Write-Host "Analyzing account usage patterns..." -ForegroundColor Yellow
$sessions = Get-NPSActivitySession

# Get action queues for scheduled tasks and service information
Write-Host "Retrieving dependency information..." -ForegroundColor Yellow
$actionQueue = Get-NPSActionQueue

# Build comprehensive dependency map
$dependencyMap = @()

foreach ($serviceAccount in $serviceAccounts) {
    Write-Host "  Mapping dependencies for: $($serviceAccount.name)" -ForegroundColor Gray
    
    # Find resources using this service account
    $associatedResources = $resources | Where-Object { $_.serviceAccountId -eq $serviceAccount.id }
    
    # Find sessions using this credential
    $accountSessions = $sessions | Where-Object { $_.credentialId -eq $serviceAccount.id }
    
    # Extract unique resources accessed
    $accessedResourceIds = $accountSessions | Select-Object -ExpandProperty managedResourceId -Unique
    $accessedResources = $resources | Where-Object { $_.id -in $accessedResourceIds }
    
    # Find related action queues (could indicate services or scheduled tasks)
    $relatedActions = $actionQueue | Where-Object { 
        $_.description -like "*$($serviceAccount.username)*" -or
        $_.description -like "*$($serviceAccount.name)*"
    }
    
    # Analyze impact
    $totalDependencies = $associatedResources.Count + $accessedResources.Count
    $uniqueResources = @($associatedResources; $accessedResources) | Select-Object -Property id -Unique
    
    # Determine criticality
    $criticality = if ($totalDependencies -gt 10) { "CRITICAL" }
    elseif ($totalDependencies -gt 5) { "HIGH" }
    elseif ($totalDependencies -gt 2) { "MEDIUM" }
    else { "LOW" }
    
    # Build dependency entry
    $dependencies = @()
    
    # Add resources where this is the service account
    foreach ($resource in $associatedResources) {
        $dependencies += [PSCustomObject]@{
            ResourceName   = $resource.name
            ResourceType   = switch ($resource.type) {
                0 { "Host" }
                1 { "Domain" }
                2 { "Website" }
                3 { "Database" }
                default { "Unknown" }
            }
            DependencyType = "Service Account"
            Platform       = $resource.platformName
            DnsHostName    = $resource.dnsHostName
            IPAddress      = $resource.ipAddress
            LastScanDate   = $resource.lastScanTimeUtc
            Status         = "Active"
        }
    }
    
    # Add resources accessed via sessions
    foreach ($resource in $accessedResources) {
        if ($resource.id -notin $associatedResources.id) {
            $resourceSessions = $accountSessions | Where-Object { $_.managedResourceId -eq $resource.id }
            $dependencies += [PSCustomObject]@{
                ResourceName   = $resource.name
                ResourceType   = switch ($resource.type) {
                    0 { "Host" }
                    1 { "Domain" }
                    2 { "Website" }
                    3 { "Database" }
                    default { "Unknown" }
                }
                DependencyType = "Session Access"
                Platform       = $resource.platformName
                DnsHostName    = $resource.dnsHostName
                IPAddress      = $resource.ipAddress
                LastAccessDate = ($resourceSessions.actualStartDateTimeUtc | Sort-Object -Descending | Select-Object -First 1)
                AccessCount    = $resourceSessions.Count
                Status         = "Active"
            }
        }
    }
    
    $dependencyMap += [PSCustomObject]@{
        ServiceAccountName    = $serviceAccount.name
        Domain                = $serviceAccount.domain
        Username              = $serviceAccount.username
        CredentialType        = switch ($serviceAccount.type) {
            1 { "Service" }
            2 { "Application" }
            default { "Other" }
        }
        TotalDependencies     = $uniqueResources.Count
        DirectServiceAccounts = $associatedResources.Count
        SessionAccessPoints   = ($accessedResources | Where-Object { $_.id -notin $associatedResources.id }).Count
        Criticality           = $criticality
        LastRotationDate      = $serviceAccount.modifiedDateTimeUtc
        DaysSinceRotation     = ([DateTime]::UtcNow - [DateTime]$serviceAccount.modifiedDateTimeUtc).Days
        ChangeOnCheckout      = $serviceAccount.changeOnCheckout
        ChangeOnRelease       = $serviceAccount.changeOnRelease
        TotalUsageCount       = $accountSessions.Count
        LastUsedDate          = ($accountSessions.actualStartDateTimeUtc | Sort-Object -Descending | Select-Object -First 1)
        Dependencies          = $dependencies
        RelatedActionsCount   = $relatedActions.Count
        CreatedDate           = $serviceAccount.createdDateTimeUtc
        IsDeleted             = $serviceAccount.isDeleted
    }
}

# Sort by criticality and total dependencies
$dependencyMap = $dependencyMap | Sort-Object @{Expression = {
        switch ($_.Criticality) {
            "CRITICAL" { 0 }
            "HIGH" { 1 }
            "MEDIUM" { 2 }
            "LOW" { 3 }
        }
    }
}, TotalDependencies -Descending

# Display summary
Write-Host "`n╔══════════════════════════════════════════════════════════════╗" -ForegroundColor Green
Write-Host "║                    Dependency Summary                        ║" -ForegroundColor Green
Write-Host "╚══════════════════════════════════════════════════════════════╝" -ForegroundColor Green
Write-Host ""
Write-Host "Total Service Accounts Analyzed: $($dependencyMap.Count)" -ForegroundColor White
Write-Host "  🔴 Critical: $(($dependencyMap | Where-Object { $_.Criticality -eq 'CRITICAL' }).Count)" -ForegroundColor Red
Write-Host "  🟠 High: $(($dependencyMap | Where-Object { $_.Criticality -eq 'HIGH' }).Count)" -ForegroundColor Yellow
Write-Host "  🟡 Medium: $(($dependencyMap | Where-Object { $_.Criticality -eq 'MEDIUM' }).Count)" -ForegroundColor DarkYellow
Write-Host "  🟢 Low: $(($dependencyMap | Where-Object { $_.Criticality -eq 'LOW' }).Count)" -ForegroundColor Green
Write-Host ""

# Display top dependencies
Write-Host "Top 10 Service Accounts by Dependency Count:" -ForegroundColor Cyan
$dependencyMap | Select-Object -First 10 | ForEach-Object {
    $color = switch ($_.Criticality) {
        "CRITICAL" { "Red" }
        "HIGH" { "Yellow" }
        "MEDIUM" { "DarkYellow" }
        "LOW" { "Green" }
    }
    Write-Host "  [$($_.Criticality.PadRight(8))] $($_.ServiceAccountName) - $($_.TotalDependencies) dependencies" -ForegroundColor $color
}

# Show impact analysis if requested
if ($ShowImpactAnalysis) {
    Write-Host "`n╔══════════════════════════════════════════════════════════════╗" -ForegroundColor Magenta
    Write-Host "║                    Impact Analysis                           ║" -ForegroundColor Magenta
    Write-Host "╚══════════════════════════════════════════════════════════════╝" -ForegroundColor Magenta
    
    foreach ($sa in ($dependencyMap | Where-Object { $_.Criticality -in @("CRITICAL", "HIGH") } | Select-Object -First 5)) {
        Write-Host "`n🔍 Service Account: $($sa.ServiceAccountName)" -ForegroundColor Cyan
        Write-Host "   Domain: $($sa.Domain)\$($sa.Username)" -ForegroundColor Gray
        Write-Host "   Criticality: $($sa.Criticality)" -ForegroundColor $(
            switch ($sa.Criticality) {
                "CRITICAL" { "Red" }
                "HIGH" { "Yellow" }
                default { "White" }
            }
        )
        Write-Host "   Total Dependencies: $($sa.TotalDependencies)" -ForegroundColor White
        Write-Host "   Last Rotation: $($sa.DaysSinceRotation) days ago" -ForegroundColor $(
            if ($sa.DaysSinceRotation -gt 90) { "Red" } 
            elseif ($sa.DaysSinceRotation -gt 60) { "Yellow" }
            else { "Green" }
        )
        
        if ($sa.Dependencies.Count -gt 0) {
            Write-Host "`n   Dependent Systems:" -ForegroundColor Yellow
            $sa.Dependencies | Select-Object -First 10 | ForEach-Object {
                Write-Host "     • $($_.ResourceName) ($($_.DependencyType)) - $($_.Platform)" -ForegroundColor Gray
            }
            if ($sa.Dependencies.Count -gt 10) {
                Write-Host "     ... and $($sa.Dependencies.Count - 10) more" -ForegroundColor DarkGray
            }
        }
        
        Write-Host "`n   💥 Impact of Password Change:" -ForegroundColor Red
        if ($sa.ChangeOnCheckout -or $sa.ChangeOnRelease) {
            Write-Host "     ✓ Auto-rotation enabled - Reduced impact" -ForegroundColor Green
        }
        else {
            Write-Host "     ⚠ Manual rotation required - High impact" -ForegroundColor Red
            Write-Host "     ⚠ $($sa.TotalDependencies) systems may experience service disruption" -ForegroundColor Red
        }
        
        if ($sa.TotalUsageCount -gt 0) {
            Write-Host "   📊 Usage Stats:" -ForegroundColor Cyan
            Write-Host "     Total Sessions: $($sa.TotalUsageCount)" -ForegroundColor White
            Write-Host "     Last Used: $(if ($sa.LastUsedDate) { ([DateTime]$sa.LastUsedDate).ToString('yyyy-MM-dd HH:mm') } else { 'Never' })" -ForegroundColor White
        }
    }
}

# Export based on format
if ($ExportPath) {
    switch ($Format) {
        'CSV' {
            # Flatten for CSV export
            $csvData = $dependencyMap | ForEach-Object {
                $sa = $_
                if ($sa.Dependencies.Count -gt 0) {
                    $sa.Dependencies | ForEach-Object {
                        [PSCustomObject]@{
                            ServiceAccountName = $sa.ServiceAccountName
                            Domain             = $sa.Domain
                            Username           = $sa.Username
                            Criticality        = $sa.Criticality
                            TotalDependencies  = $sa.TotalDependencies
                            DaysSinceRotation  = $sa.DaysSinceRotation
                            DependentResource  = $_.ResourceName
                            DependencyType     = $_.DependencyType
                            ResourcePlatform   = $_.Platform
                            ResourceDNS        = $_.DnsHostName
                            ResourceIP         = $_.IPAddress
                        }
                    }
                }
                else {
                    [PSCustomObject]@{
                        ServiceAccountName = $sa.ServiceAccountName
                        Domain             = $sa.Domain
                        Username           = $sa.Username
                        Criticality        = $sa.Criticality
                        TotalDependencies  = 0
                        DaysSinceRotation  = $sa.DaysSinceRotation
                        DependentResource  = "No dependencies"
                        DependencyType     = "N/A"
                        ResourcePlatform   = "N/A"
                        ResourceDNS        = "N/A"
                        ResourceIP         = "N/A"
                    }
                }
            }
            $csvData | Export-Csv -Path $ExportPath -NoTypeInformation
            Write-Host "`n✓ CSV report exported to: $ExportPath" -ForegroundColor Green
        }
        'JSON' {
            $exportData = @{
                GeneratedDate              = Get-Date
                TotalServiceAccounts       = $dependencyMap.Count
                CriticalAccounts           = ($dependencyMap | Where-Object { $_.Criticality -eq 'CRITICAL' }).Count
                HighRiskAccounts           = ($dependencyMap | Where-Object { $_.Criticality -eq 'HIGH' }).Count
                ServiceAccountDependencies = $dependencyMap
            }
            $exportData | ConvertTo-Json -Depth 10 | Out-File -FilePath $ExportPath
            Write-Host "`n✓ JSON report exported to: $ExportPath" -ForegroundColor Green
        }
        'HTML' {
            $html = @"
<!DOCTYPE html>
<html>
<head>
    <title>NPS Service Account Dependency Map</title>
    <style>
        body { font-family: 'Segoe UI', Arial, sans-serif; margin: 20px; background: #f5f5f5; }
        h1 { color: #2c3e50; border-bottom: 3px solid #3498db; padding-bottom: 10px; }
        .summary { background: white; padding: 20px; border-radius: 8px; margin: 20px 0; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        .account-card { background: white; margin: 20px 0; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        .critical { border-left: 5px solid #e74c3c; }
        .high { border-left: 5px solid #f39c12; }
        .medium { border-left: 5px solid #f1c40f; }
        .low { border-left: 5px solid #27ae60; }
        .badge { padding: 4px 12px; border-radius: 12px; font-size: 0.9em; font-weight: bold; color: white; display: inline-block; }
        .badge-critical { background: #e74c3c; }
        .badge-high { background: #f39c12; }
        .badge-medium { background: #f1c40f; color: #333; }
        .badge-low { background: #27ae60; }
        table { width: 100%; border-collapse: collapse; margin-top: 10px; }
        th { background: #34495e; color: white; padding: 10px; text-align: left; }
        td { padding: 8px; border-bottom: 1px solid #ddd; }
        tr:hover { background: #f9f9f9; }
        .stat-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; margin: 20px 0; }
        .stat-box { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 20px; border-radius: 8px; text-align: center; }
        .stat-value { font-size: 2.5em; font-weight: bold; }
        .stat-label { font-size: 0.9em; opacity: 0.9; }
        .dependency-list { list-style: none; padding: 0; }
        .dependency-item { padding: 8px; margin: 5px 0; background: #ecf0f1; border-radius: 4px; }
    </style>    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
</head>
<body>
    <h1>🔐 Service Account Dependency Map</h1>
    <p>Generated: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")</p>
    
    <div class="summary">
        <h2>Overview</h2>
        <div class="stat-grid">
            <div class="stat-box" style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);">
                <div class="stat-value">$($dependencyMap.Count)</div>
                <div class="stat-label">Service Accounts</div>
            </div>
            <div class="stat-box" style="background: linear-gradient(135deg, #f093fb 0%, #f5576c 100%);">
                <div class="stat-value">$(($dependencyMap | Where-Object { $_.Criticality -eq 'CRITICAL' }).Count)</div>
                <div class="stat-label">Critical</div>
            </div>
            <div class="stat-box" style="background: linear-gradient(135deg, #fa709a 0%, #fee140 100%);">
                <div class="stat-value">$(($dependencyMap | Where-Object { $_.Criticality -eq 'HIGH' }).Count)</div>
                <div class="stat-label">High Risk</div>
            </div>
            <div class="stat-box" style="background: linear-gradient(135deg, #a8edea 0%, #fed6e3 100%);">
                <div class="stat-value">$(($dependencyMap | Measure-Object -Property TotalDependencies -Sum).Sum)</div>
                <div class="stat-label">Total Dependencies</div>
            </div>
        </div>
    </div>
    
    <h2>Service Account Details</h2>
"@
            foreach ($sa in $dependencyMap) {
                $badgeClass = "badge-$($sa.Criticality.ToLower())"
                $cardClass = $sa.Criticality.ToLower()
                $rotationColor = if ($sa.DaysSinceRotation -gt 90) { "red" } elseif ($sa.DaysSinceRotation -gt 60) { "orange" } else { "green" }
                
                $html += @"
    <div class="account-card $cardClass">
        <h3>$($sa.ServiceAccountName) <span class="badge $badgeClass">$($sa.Criticality)</span></h3>
        <p><strong>Account:</strong> $($sa.Domain)\$($sa.Username)</p>
        <p><strong>Type:</strong> $($sa.CredentialType)</p>
        <p><strong>Total Dependencies:</strong> $($sa.TotalDependencies)</p>
        <p><strong>Last Rotation:</strong> <span style="color: $rotationColor; font-weight: bold;">$($sa.DaysSinceRotation) days ago</span></p>
        <p><strong>Auto-Rotation:</strong> $(if ($sa.ChangeOnCheckout -or $sa.ChangeOnRelease) { "✓ Enabled" } else { "✗ Disabled" })</p>
        <p><strong>Usage Count:</strong> $($sa.TotalUsageCount) sessions</p>
        
        $(if ($sa.Dependencies.Count -gt 0) {
            "<h4>Dependent Systems:</h4><ul class='dependency-list'>"
            ($sa.Dependencies | Select-Object -First 15 | ForEach-Object {
                "<li class='dependency-item'><strong>$($_.ResourceName)</strong> ($($_.DependencyType)) - $($_.Platform)</li>"
            }) -join ""
            if ($sa.Dependencies.Count -gt 15) {
                "<li class='dependency-item' style='font-style: italic;'>... and $($sa.Dependencies.Count - 15) more dependencies</li>"
            }
            "</ul>"
        } else {
            "<p><em>No dependencies found</em></p>"
        })
    </div>
"@
            }
            
            $html += @"
</body>
</html>
"@
            $html | Out-File -FilePath $ExportPath
            Write-Host "`n✓ HTML dependency map exported to: $ExportPath" -ForegroundColor Green
        }
    }
}

Write-Host "`n✓ Service account dependency mapping complete!" -ForegroundColor Green
Write-Host "`n💡 Tip: Use this report for:" -ForegroundColor Cyan
Write-Host "   • Planning password rotations" -ForegroundColor White
Write-Host "   • Assessing change impact" -ForegroundColor White
Write-Host "   • Disaster recovery planning" -ForegroundColor White
Write-Host "   • Security incident response" -ForegroundColor White
