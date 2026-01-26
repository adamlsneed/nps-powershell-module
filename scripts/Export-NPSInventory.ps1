<#
.SYNOPSIS
    Export NPS Managed Resources to CSV
    
.DESCRIPTION
    This script connects to NPS and exports all managed resources and their
    associated details to a CSV file for inventory management.
#>

param(
    [string]$Server = "https://nps.adamsneed.com:6500",
    [string]$Username = "adamsneed\asneed",
    [SecureString]$Password,
    [string]$MfaCode = "123456",
    [string]$OutputPath = "./NPS_Inventory.csv"
)

Import-Module ./NPS-Module-Complete.psm1 -Force

# Authenticate
if (-not (Test-NPSConnection)) {
    Write-Host "Connecting to NPS..." -ForegroundColor Cyan
    Connect-NPSServer -Server $Server -Username $Username -Password $Password -MfaCode $MfaCode -SkipCertificateCheck
}

if (-not (Test-NPSConnection)) {
    Write-Error "Could not connect to NPS server."
    return
}

Write-Host "Retrieving managed resources..." -ForegroundColor Yellow
$resources = Get-NPSManagedResource

Write-Host "Found $($resources.Count) resources. Exporting to $OutputPath..." -ForegroundColor Green

$resources | Select-Object id, name, ipAddress, platformName, dnsHostName, createdDateTimeUtc | Export-Csv -Path $OutputPath -NoTypeInformation

Write-Host "Export complete." -ForegroundColor Green
