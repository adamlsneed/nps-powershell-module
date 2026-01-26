# Test script for NPS PowerShell Module
Import-Module ./NPS-Module-Complete.psm1 -Force

$Server = "https://nps.adamsneed.com:6500"
$User = "adamsneed\asneed"
$Pass = "Temp123!"
$Mfa = "123456"

Write-Host "--- Testing Connection ---" -ForegroundColor Cyan
$connected = Connect-NPSServer -Server $Server -Username $User -Password $Pass -MfaCode $Mfa -SkipCertificateCheck
if (-not $connected) {
    Write-Error "Failed to connect to NPS server"
    exit 1
}

Write-Host "`n--- Testing System Cmdlets ---" -ForegroundColor Cyan
Get-NPSVersion | Out-String | Write-Host
Get-NPSHealth | Out-String | Write-Host
Get-NPSLicenseInfo | Select-Object -First 1 | Out-String | Write-Host

Write-Host "`n--- Testing Managed Resources ---" -ForegroundColor Cyan
$resources = Get-NPSManagedResource
Write-Host "Found $($resources.Count) resources"
$resources | Select-Object -First 2 | Out-String | Write-Host

Write-Host "`n--- Testing Credentials ---" -ForegroundColor Cyan
$creds = Get-NPSCredential
Write-Host "Found $($creds.Count) credentials"
$creds | Select-Object -First 2 | Out-String | Write-Host

Write-Host "`n--- Testing Activity Sessions ---" -ForegroundColor Cyan
$sessions = Get-NPSActivitySession
Write-Host "Found $($sessions.Count) sessions"
$sessions | Select-Object -First 2 | Out-String | Write-Host

Write-Host "`n--- Testing Search Pagination ---" -ForegroundColor Cyan
$search = Get-NPSManagedResource -Search -First 5
Write-Host "Search Records Total: $($search.recordsTotal)"
Write-Host "Search Data Count: $($search.data.Count)"

Write-Host "`n--- Testing Disconnect ---" -ForegroundColor Cyan
Disconnect-NPSServer
Write-Host "Test connection after disconnect..."
if (-not (Test-NPSConnection)) {
    Write-Host "✓ Successfully disconnected" -ForegroundColor Green
}
else {
    Write-Error "Failed to disconnect"
}
