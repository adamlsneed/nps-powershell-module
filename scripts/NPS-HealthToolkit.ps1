<#
.SYNOPSIS
    NPS Health Check & Inventory Toolkit
    
.DESCRIPTION
    This script provides a high-level tool for administrators to:
    1. Check health of all NPS services
    2. List managed resources with their status
    3. Identify resources with pending actions
    4. Export a summary report
#>

param(
    [string]$Server = "https://nps.lab.example.com:6500",
    [string]$Username = "adamsneed\asneed",
    [SecureString]$Password,
    [string]$MfaCode = "123456"
)

Import-Module ./NPS-Module-Complete.psm1 -Force

# Authenticate if not already connected
if (-not (Test-NPSConnection)) {
    Write-Host "Connecting to NPS..." -ForegroundColor Cyan
    Connect-NPSServer -Server $Server -Username $Username -Password $Password -MfaCode $MfaCode -SkipCertificateCheck
}

if (-not (Test-NPSConnection)) {
    Write-Error "Could not connect to NPS server."
    return
}

Write-Host "`n=== NPS Health Status ===" -ForegroundColor Yellow
$health = Get-NPSHealth
Write-Host "System Health: $health" -ForegroundColor (if ($health -eq "Healthy") { "Green" }else { "Red" })

$version = Get-NPSVersion
Write-Host "NPS Version: $version"

Write-Host "`n=== Service Inventory ===" -ForegroundColor Yellow
$services = Get-NPSServiceRegistration
$services | Select-Object serviceName, dnsHostName, type | Format-Table -AutoSize

Write-Host "`n=== Resource Status Summary ===" -ForegroundColor Yellow
$resources = Get-NPSManagedResource
$resourceSummary = $resources | Group-Object platformName | Select-Object @{n = "Platform"; e = { $_.Name } }, @{n = "Count"; e = { $_.Count } }
$resourceSummary | Format-Table -AutoSize

Write-Host "`n=== Active Session Monitor ===" -ForegroundColor Yellow
$sessions = Get-NPSActivitySession -Active
Write-Host "Current Active Sessions: $($sessions.Count)" -ForegroundColor Cyan
if ($sessions.Count -gt 0) {
    $sessions | Select-Object createdByUserName, loginAccountName, statusDescription | Format-Table -AutoSize
}

Write-Host "`nToolkit execution complete." -ForegroundColor Green
