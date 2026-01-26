<#
.SYNOPSIS
    Comprehensive test suite for NPS PowerShell Module.

.DESCRIPTION
    Tests all major cmdlets and functionality of the NPS module:
    - Connection and authentication
    - System health and version checks
    - Resource management
    - Credential operations
    - Session management
    - Search and pagination
    - Error handling

.PARAMETER Server
    NPS server URL

.PARAMETER Username
    Username for authentication

.PARAMETER Password
    Password for authentication

.PARAMETER MfaCode
    6-digit MFA code

.PARAMETER Detailed
    Show detailed test output

.PARAMETER ExportResults
    Export test results to JSON file

.EXAMPLE
    .\Test-NPSModule.ps1 -Detailed

    Runs comprehensive tests with detailed output.

.EXAMPLE
    .\Test-NPSModule.ps1 -ExportResults "./test_results.json"

    Runs tests and exports results.
#>

[CmdletBinding()]
param(
    [Parameter()]
    [string]$Server = "https://nps.adamsneed.com:6500",

    [Parameter()]
    [string]$Username = "adamsneed\asneed",

    [Parameter()]
    [string]$Password = "Temp123!",

    [Parameter()]
    [string]$MfaCode = "123456",

    [Parameter()]
    [switch]$Detailed,

    [Parameter()]
    [string]$ExportResults
)

Import-Module "$PSScriptRoot/../NPS-Module-Complete.psm1" -Force

$testResults = @()
$passCount = 0
$failCount = 0

function Write-TestHeader {
    param([string]$Message)
    Write-Host "`n╔══════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "║ $($Message.PadRight(60)) ║" -ForegroundColor Cyan
    Write-Host "╚══════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
}

function Test-Cmdlet {
    param(
        [string]$Name,
        [scriptblock]$ScriptBlock,
        [string]$ExpectedResult = "Success"
    )
    
    $testResult = @{
        TestName  = $Name
        Status    = "Failed"
        Duration  = 0
        Error     = $null
        Result    = $null
        Timestamp = Get-Date
    }
    
    try {
        $sw = [System.Diagnostics.Stopwatch]::StartNew()
        $result = & $ScriptBlock
        $sw.Stop()
        
        $testResult.Duration = $sw.ElapsedMilliseconds
        $testResult.Result = $result
        
        if ($ExpectedResult -eq "Success" -and $null -ne $result) {
            $testResult.Status = "Passed"
            $script:passCount++
            Write-Host "  ✓ $Name " -ForegroundColor Green -NoNewline
            Write-Host "($($sw.ElapsedMilliseconds)ms)" -ForegroundColor Gray
            
            if ($Detailed -and $result) {
                $result | Format-List | Out-String | Write-Host -ForegroundColor DarkGray
            }
        }
        elseif ($null -eq $result -and $ExpectedResult -eq "Success") {
            $testResult.Status = "Warning"
            Write-Host "  ⚠ $Name (No data returned)" -ForegroundColor Yellow
        }
        else {
            $testResult.Status = "Passed"
            $script:passCount++
            Write-Host "  ✓ $Name " -ForegroundColor Green -NoNewline
            Write-Host "($($sw.ElapsedMilliseconds)ms)" -ForegroundColor Gray
        }
    }
    catch {
        $testResult.Status = "Failed"
        $testResult.Error = $_.Exception.Message
        $script:failCount++
        Write-Host "  ✗ $Name" -ForegroundColor Red
        if ($Detailed) {
            Write-Host "    Error: $($_.Exception.Message)" -ForegroundColor DarkRed
        }
    }
    
    $script:testResults += $testResult
}

# Start testing
Write-Host "`n╔══════════════════════════════════════════════════════════════╗" -ForegroundColor Magenta
Write-Host "║             NPS PowerShell Module Test Suite                ║" -ForegroundColor Magenta
Write-Host "╚══════════════════════════════════════════════════════════════╝" -ForegroundColor Magenta
Write-Host "Started: $(Get-Date)" -ForegroundColor White

# Test 1: Connection
Write-TestHeader "Authentication & Connection Tests"
Test-Cmdlet -Name "Connect to NPS Server" -ScriptBlock {
    Connect-NPSServer -Server $Server -Username $Username -Password $Password -MfaCode $MfaCode -SkipCertificateCheck
}

Test-Cmdlet -Name "Test Connection" -ScriptBlock {
    Test-NPSConnection
}

Test-Cmdlet -Name "Test Connection with Live Check" -ScriptBlock {
    Test-NPSConnection -LiveCheck
}

# Test 2: System Information
Write-TestHeader "System Information Tests"
Test-Cmdlet -Name "Get NPS Version" -ScriptBlock {
    Get-NPSVersion
}

Test-Cmdlet -Name "Get NPS Health" -ScriptBlock {
    Get-NPSHealth
}

Test-Cmdlet -Name "Get License Info" -ScriptBlock {
    Get-NPSLicenseInfo
}

# Test 3: Resources
Write-TestHeader "Resource Management Tests"
Test-Cmdlet -Name "Get Managed Resources (All)" -ScriptBlock {
    Get-NPSManagedResource
}

Test-Cmdlet -Name "Get Managed Resources (Search)" -ScriptBlock {
    Get-NPSManagedResource -Search -First 10
}

Test-Cmdlet -Name "Get Managed Accounts" -ScriptBlock {
    Get-NPSManagedAccount
}

Test-Cmdlet -Name "Get Platforms" -ScriptBlock {
    Get-NPSPlatform
}

# Test 4: Credentials
Write-TestHeader "Credential Management Tests"
Test-Cmdlet -Name "Get Credentials" -ScriptBlock {
    Get-NPSCredential
}

Test-Cmdlet -Name "Get Credential Types" -ScriptBlock {
    Get-NPSCredentialTypes
}

Test-Cmdlet -Name "Get Authentication Method Types" -ScriptBlock {
    Get-NPSAuthenticationMethodTypes
}

# Test 5: Activity & Sessions
Write-TestHeader "Activity & Session Tests"
Test-Cmdlet -Name "Get Activities" -ScriptBlock {
    Get-NPSActivity
}

Test-Cmdlet -Name "Get Activity Sessions" -ScriptBlock {
    Get-NPSActivitySession
}

Test-Cmdlet -Name "Get Activity Session Count" -ScriptBlock {
    Get-NPSActivitySessionCount
}

Test-Cmdlet -Name "Get Activity Session Configuration" -ScriptBlock {
    Get-NPSActivitySessionConfiguration
}

# Test 6: Policies
Write-TestHeader "Policy & Security Tests"
Test-Cmdlet -Name "Get Access Control Policies" -ScriptBlock {
    Get-NPSAccessControlPolicy
}

Test-Cmdlet -Name "Get User Policies" -ScriptBlock {
    Get-NPSUserPolicy
}

# Test 7: Action Management
Write-TestHeader "Action Management Tests"
Test-Cmdlet -Name "Get Action Groups" -ScriptBlock {
    Get-NPSActionGroup
}

Test-Cmdlet -Name "Get Action Jobs" -ScriptBlock {
    Get-NPSActionJob
}

Test-Cmdlet -Name "Get Action Queue" -ScriptBlock {
    Get-NPSActionQueue
}

# Test 8: Domain & Network
Write-TestHeader "Domain & Network Tests"
Test-Cmdlet -Name "Get Domains" -ScriptBlock {
    $resources = Get-NPSManagedResource
    $domainResource = $resources | Where-Object { $_.type -eq 1 } | Select-Object -First 1
    if ($domainResource) {
        Get-NPSDomain -Id $domainResource.domainConfigId
    }
}

# Test 9: Search Functionality
Write-TestHeader "Search & Pagination Tests"
Test-Cmdlet -Name "Search Resources with Pagination" -ScriptBlock {
    $result = Get-NPSManagedResource -Search -First 5
    [PSCustomObject]@{
        RecordsTotal      = $result.recordsTotal
        RecordsFiltered   = $result.recordsFiltered
        DataCount         = $result.data.Count
        CorrectPagination = ($result.data.Count -eq 5)
    }
}

Test-Cmdlet -Name "Search Credentials" -ScriptBlock {
    Get-NPSCredential -Search -First 3
}

# Test 10: Advanced Features
Write-TestHeader "Advanced Feature Tests"
Test-Cmdlet -Name "Convert JWT Token" -ScriptBlock {
    $tokenObj = Convert-NPSToken -Token $Script:NPSSession.Token
    [PSCustomObject]@{
        HasManagedAccountId = ($null -ne $tokenObj.managedAccountId)
        HasUsername         = ($null -ne $tokenObj.unique_name)
    }
}

Test-Cmdlet -Name "Get User Token (Token Decoding)" -ScriptBlock {
    Convert-NPSToken -Token $Script:NPSSession.Token
}

# Test 11: Disconnection
Write-TestHeader "Disconnection Tests"
Test-Cmdlet -Name "Disconnect from NPS" -ScriptBlock {
    Disconnect-NPSServer
    -not (Test-NPSConnection)
}

# Test Results Summary
Write-Host "`n╔══════════════════════════════════════════════════════════════╗" -ForegroundColor Magenta
Write-Host "║                    Test Results Summary                     ║" -ForegroundColor Magenta
Write-Host "╚══════════════════════════════════════════════════════════════╝" -ForegroundColor Magenta
Write-Host "`nTotal Tests: $($passCount + $failCount)" -ForegroundColor White
Write-Host "Passed: $passCount" -ForegroundColor Green
Write-Host "Failed: $failCount" -ForegroundColor Red
$successRate = [math]::Round(($passCount / ($passCount + $failCount)) * 100, 2)
Write-Host "Success Rate: $successRate%" -ForegroundColor $(if ($successRate -ge 90) { "Green" } elseif ($successRate -ge 70) { "Yellow" } else { "Red" })

if ($failCount -gt 0) {
    Write-Host "`nFailed Tests:" -ForegroundColor Red
    $testResults | Where-Object { $_.Status -eq "Failed" } | ForEach-Object {
        Write-Host "  • $($_.TestName)" -ForegroundColor Red
        if ($_.Error) {
            Write-Host "    $($_.Error)" -ForegroundColor DarkRed
        }
    }
}

# Export results if requested
if ($ExportResults) {
    $exportData = @{
        TestRun         = Get-Date
        Server          = $Server
        TotalTests      = $passCount + $failCount
        Passed          = $passCount
        Failed          = $failCount
        SuccessRate     = $successRate
        DetailedResults = $testResults
    }
    
    $exportData | ConvertTo-Json -Depth 10 | Out-File -FilePath $ExportResults
    Write-Host "`nTest results exported to: $ExportResults" -ForegroundColor Cyan
}

Write-Host "`nTest suite completed at $(Get-Date)" -ForegroundColor White
Write-Host "═══════════════════════════════════════════════════════════════`n" -ForegroundColor Magenta

# Return exit code
if ($failCount -eq 0) { exit 0 } else { exit 1 }
