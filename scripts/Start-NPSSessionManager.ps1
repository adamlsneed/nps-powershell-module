<#
.SYNOPSIS
    Interactive session manager for NPS activity sessions.

.DESCRIPTION
    Provides an interactive menu-driven interface for managing NPS activity sessions:
    - Start new sessions
    - View active sessions
    - Retrieve session passwords
    - Extend sessions
    - Stop sessions
    - Monitor session activity

.EXAMPLE
    .\Start-NPSSessionManager.ps1

    Launches the interactive session manager.
#>

[CmdletBinding()]
param()

Import-Module "$PSScriptRoot/../NPS-Module-Complete.psm1" -Force

# Verify connection
if (-not (Test-NPSConnection)) {
    Write-Error "Not connected to NPS. Please run Connect-NPSServer first."
    exit 1
}

function Show-Menu {
    Clear-Host
    Write-Host "╔══════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "║        NPS Activity Session Manager                     ║" -ForegroundColor Cyan
    Write-Host "╚══════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  1. Start New Session" -ForegroundColor Green
    Write-Host "  2. View Active Sessions" -ForegroundColor Yellow
    Write-Host "  3. View All Sessions" -ForegroundColor White
    Write-Host "  4. Get Session Password" -ForegroundColor Magenta
    Write-Host "  5. Stop Session" -ForegroundColor Red
    Write-Host "  6. Search Sessions" -ForegroundColor Cyan
    Write-Host "  7. Session Summary" -ForegroundColor Blue
    Write-Host "  8. Refresh" -ForegroundColor Gray
    Write-Host "  Q. Quit" -ForegroundColor DarkGray
    Write-Host ""
}

function Start-NewSession {
    Write-Host "`n=== Start New Session ===" -ForegroundColor Green
    
    # Get available resources
    Write-Host "Fetching available resources..." -ForegroundColor Gray
    $resources = Get-NPSManagedResource -Search -First 20
    
    if ($resources.data.Count -eq 0) {
        Write-Host "No resources found!" -ForegroundColor Red
        Read-Host "Press Enter to continue"
        return
    }
    
    # Display resources
    Write-Host "`nAvailable Resources:" -ForegroundColor Cyan
    for ($i = 0; $i -lt $resources.data.Count; $i++) {
        Write-Host "  [$i] $($resources.data[$i].name) - $($resources.data[$i].platformName)"
    }
    
    $resourceIndex = Read-Host "`nSelect resource number"
    if ([int]$resourceIndex -lt 0 -or [int]$resourceIndex -ge $resources.data.Count) {
        Write-Host "Invalid selection!" -ForegroundColor Red
        Read-Host "Press Enter to continue"
        return
    }
    
    $selectedResource = $resources.data[[int]$resourceIndex]
    
    # Get available credentials
    Write-Host "`nFetching available credentials..." -ForegroundColor Gray
    $credentials = Get-NPSCredential
    $resourceCreds = $credentials | Where-Object { $_.platformId -eq $selectedResource.platformId }
    
    if ($resourceCreds.Count -eq 0) {
        Write-Host "No compatible credentials found!" -ForegroundColor Red
        Read-Host "Press Enter to continue"
        return
    }
    
    # Display credentials
    Write-Host "`nAvailable Credentials:" -ForegroundColor Cyan
    for ($i = 0; $i -lt $resourceCreds.Count; $i++) {
        Write-Host "  [$i] $($resourceCreds[$i].name)"
    }
    
    $credIndex = Read-Host "`nSelect credential number"
    if ([int]$credIndex -lt 0 -or [int]$credIndex -ge $resourceCreds.Count) {
        Write-Host "Invalid selection!" -ForegroundColor Red
        Read-Host "Press Enter to continue"
        return
    }
    
    $selectedCred = $resourceCreds[[int]$credIndex]
    
    # Get activities
    Write-Host "`nAvailable Activities:" -ForegroundColor Cyan
    $activities = @("RDP", "SSH", "CredentialRelease", "PowerShell", "WinRM")
    for ($i = 0; $i -lt $activities.Count; $i++) {
        Write-Host "  [$i] $($activities[$i])"
    }
    
    $activityIndex = Read-Host "`nSelect activity number"
    if ([int]$activityIndex -lt 0 -or [int]$activityIndex -ge $activities.Count) {
        Write-Host "Invalid selection!" -ForegroundColor Red
        Read-Host "Press Enter to continue"
        return
    }
    
    $selectedActivity = $activities[[int]$activityIndex]
    
    # Create session
    Write-Host "`nCreating session..." -ForegroundColor Yellow
    try {
        $session = Start-NPSActivitySession `
            -ActivityName $selectedActivity `
            -ResourceId $selectedResource.id `
            -CredentialId $selectedCred.id
        
        Write-Host "`n✓ Session created successfully!" -ForegroundColor Green
        Write-Host "  Session ID: $($session.id)" -ForegroundColor White
        Write-Host "  Resource: $($selectedResource.name)" -ForegroundColor White
        Write-Host "  Credential: $($selectedCred.name)" -ForegroundColor White
        Write-Host "  Activity: $selectedActivity" -ForegroundColor White
    }
    catch {
        Write-Host "`n✗ Failed to create session: $_" -ForegroundColor Red
    }
    
    Read-Host "`nPress Enter to continue"
}

function Show-ActiveSessions {
    Write-Host "`n=== Active Sessions ===" -ForegroundColor Yellow
    
    $sessions = Get-NPSActivitySession
    $activeSessions = $sessions | Where-Object { $_.status -in @(1, 2) }
    
    if ($activeSessions.Count -eq 0) {
        Write-Host "No active sessions." -ForegroundColor Gray
    }
    else {
        $activeSessions | Select-Object @{
            Name       = 'ID'
            Expression = { $_.id.ToString().Substring(0, 8) }
        }, @{
            Name       = 'User'
            Expression = { $_.createdByUserName }
        }, @{
            Name       = 'Resource'
            Expression = { $_.managedResourceName }
        }, @{
            Name       = 'Activity'
            Expression = { $_.activityName }
        }, @{
            Name       = 'Status'
            Expression = { $_.statusDescription }
        }, @{
            Name       = 'Started'
            Expression = { $_.actualStartDateTimeUtc }
        } | Format-Table -AutoSize
    }
    
    Read-Host "`nPress Enter to continue"
}

function Show-AllSessions {
    Write-Host "`n=== All Sessions (Last 20) ===" -ForegroundColor White
    
    $sessions = Get-NPSActivitySession | Select-Object -First 20
    
    $sessions | Select-Object @{
        Name       = 'ID'
        Expression = { $_.id.ToString().Substring(0, 8) }
    }, @{
        Name       = 'User'
        Expression = { $_.createdByUserName }
    }, @{
        Name       = 'Resource'
        Expression = { $_.managedResourceName }
    }, @{
        Name       = 'Activity'
        Expression = { $_.activityName }
    }, @{
        Name       = 'Status'
        Expression = { $_.statusDescription }
    }, @{
        Name       = 'Started'
        Expression = { $_.actualStartDateTimeUtc }
    } | Format-Table -AutoSize
    
    Read-Host "`nPress Enter to continue"
}

function Get-SessionPasswordInteractive {
    Write-Host "`n=== Get Session Password ===" -ForegroundColor Magenta
    
    $sessions = Get-NPSActivitySession
    $activeSessions = $sessions | Where-Object { $_.status -eq 1 }
    
    if ($activeSessions.Count -eq 0) {
        Write-Host "No active sessions available." -ForegroundColor Gray
        Read-Host "Press Enter to continue"
        return
    }
    
    # Display sessions
    Write-Host "`nActive Sessions:" -ForegroundColor Cyan
    for ($i = 0; $i -lt $activeSessions.Count; $i++) {
        Write-Host "  [$i] $($activeSessions[$i].managedResourceName) - $($activeSessions[$i].loginAccountName)"
    }
    
    $sessionIndex = Read-Host "`nSelect session number"
    if ([int]$sessionIndex -lt 0 -or [int]$sessionIndex -ge $activeSessions.Count) {
        Write-Host "Invalid selection!" -ForegroundColor Red
        Read-Host "Press Enter to continue"
        return
    }
    
    $selectedSession = $activeSessions[[int]$sessionIndex]
    
    try {
        $password = Get-NPSActivitySessionPassword -Id $selectedSession.id
        Write-Host "`n✓ Password retrieved:" -ForegroundColor Green
        Write-Host "  $password" -ForegroundColor Yellow
        Write-Host "`n⚠ Password will be cleared from screen in 30 seconds..." -ForegroundColor DarkYellow
        Start-Sleep -Seconds 30
    }
    catch {
        Write-Host "`n✗ Failed to retrieve password: $_" -ForegroundColor Red
        Read-Host "Press Enter to continue"
    }
}

function Stop-SessionInteractive {
    Write-Host "`n=== Stop Session ===" -ForegroundColor Red
    
    $sessions = Get-NPSActivitySession
    $activeSessions = $sessions | Where-Object { $_.status -eq 1 }
    
    if ($activeSessions.Count -eq 0) {
        Write-Host "No active sessions to stop." -ForegroundColor Gray
        Read-Host "Press Enter to continue"
        return
    }
    
    # Display sessions
    Write-Host "`nActive Sessions:" -ForegroundColor Cyan
    for ($i = 0; $i -lt $activeSessions.Count; $i++) {
        Write-Host "  [$i] $($activeSessions[$i].managedResourceName) - $($activeSessions[$i].createdByUserName)"
    }
    
    $sessionIndex = Read-Host "`nSelect session number to stop"
    if ([int]$sessionIndex -lt 0 -or [int]$sessionIndex -ge $activeSessions.Count) {
        Write-Host "Invalid selection!" -ForegroundColor Red
        Read-Host "Press Enter to continue"
        return
    }
    
    $selectedSession = $activeSessions[[int]$sessionIndex]
    
    $confirm = Read-Host "`nAre you sure you want to stop this session? (y/N)"
    if ($confirm -eq 'y' -or $confirm -eq 'Y') {
        try {
            Stop-NPSActivitySession -Id $selectedSession.id
            Write-Host "`n✓ Session stopped successfully!" -ForegroundColor Green
        }
        catch {
            Write-Host "`n✗ Failed to stop session: $_" -ForegroundColor Red
        }
    }
    else {
        Write-Host "`nCancelled." -ForegroundColor Gray
    }
    
    Read-Host "Press Enter to continue"
}

function Search-SessionsInteractive {
    Write-Host "`n=== Search Sessions ===" -ForegroundColor Cyan
    
    $searchTerm = Read-Host "Enter search term (resource, user, or activity name)"
    
    if ([string]::IsNullOrWhiteSpace($searchTerm)) {
        Write-Host "Search cancelled." -ForegroundColor Gray
        Read-Host "Press Enter to continue"
        return
    }
    
    $sessions = Get-NPSActivitySession
    $results = $sessions | Where-Object { 
        $_.managedResourceName -like "*$searchTerm*" -or 
        $_.createdByUserName -like "*$searchTerm*" -or 
        $_.activityName -like "*$searchTerm*"
    }
    
    if ($results.Count -eq 0) {
        Write-Host "`nNo sessions found matching '$searchTerm'." -ForegroundColor Gray
    }
    else {
        Write-Host "`nFound $($results.Count) session(s):" -ForegroundColor Green
        $results | Select-Object @{
            Name       = 'Resource'
            Expression = { $_.managedResourceName }
        }, @{
            Name       = 'User'
            Expression = { $_.createdByUserName }
        }, @{
            Name       = 'Activity'
            Expression = { $_.activityName }
        }, @{
            Name       = 'Status'
            Expression = { $_.statusDescription }
        }, @{
            Name       = 'Started'
            Expression = { $_.actualStartDateTimeUtc }
        } | Format-Table -AutoSize
    }
    
    Read-Host "`nPress Enter to continue"
}

function Show-SessionSummary {
    Write-Host "`n=== Session Summary ===" -ForegroundColor Blue
    
    $sessions = Get-NPSActivitySession
    
    Write-Host "`nTotal Sessions: $($sessions.Count)" -ForegroundColor White
    Write-Host "Active Sessions: $(($sessions | Where-Object { $_.status -eq 1 }).Count)" -ForegroundColor Green
    Write-Host "Pending Sessions: $(($sessions | Where-Object { $_.status -eq 2 }).Count)" -ForegroundColor Yellow
    Write-Host "Completed Sessions: $(($sessions | Where-Object { $_.status -eq 3 }).Count)" -ForegroundColor Gray
    Write-Host "Cancelled Sessions: $(($sessions | Where-Object { $_.status -eq 4 }).Count)" -ForegroundColor Red
    
    Write-Host "`nTop 5 Activities:" -ForegroundColor Cyan
    $sessions | Group-Object activityName | Sort-Object Count -Descending | Select-Object -First 5 | ForEach-Object {
        Write-Host "  $($_.Name): $($_.Count)"
    }
    
    Write-Host "`nTop 5 Users:" -ForegroundColor Cyan
    $sessions | Group-Object createdByUserName | Sort-Object Count -Descending | Select-Object -First 5 | ForEach-Object {
        Write-Host "  $($_.Name): $($_.Count)"
    }
    
    Write-Host "`nTop 5 Resources:" -ForegroundColor Cyan
    $sessions | Group-Object managedResourceName | Sort-Object Count -Descending | Select-Object -First 5 | ForEach-Object {
        Write-Host "  $($_.Name): $($_.Count)"
    }
    
    Read-Host "`nPress Enter to continue"
}

# Main loop
do {
    Show-Menu
    $choice = Read-Host "Select an option"
    
    switch ($choice) {
        '1' { Start-NewSession }
        '2' { Show-ActiveSessions }
        '3' { Show-AllSessions }
        '4' { Get-SessionPasswordInteractive }
        '5' { Stop-SessionInteractive }
        '6' { Search-SessionsInteractive }
        '7' { Show-SessionSummary }
        '8' { continue }
        'Q' { 
            Write-Host "`nGoodbye!" -ForegroundColor Cyan
            break
        }
        default {
            Write-Host "`nInvalid choice. Please try again." -ForegroundColor Red
            Start-Sleep -Seconds 2
        }
    }
} while ($choice -ne 'Q')
