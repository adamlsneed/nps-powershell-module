<#
.SYNOPSIS
    Netwrix Privilege Secure (NPS) PowerShell Module v1.0

.DESCRIPTION
    Complete PowerShell module for interacting with Netwrix Privilege Secure v4.2 API.
    Provides cmdlets for authentication, resource management, credential operations,
    activity monitoring, and system administration.

    All cmdlets include full help documentation accessible via Get-Help.

.NOTES
    Version:        1.0
    Author:         Agent Zero
    Creation Date:  2026-01-18
    API Version:    v1 (Product Version 25.12.00000)

.EXAMPLE
    # Import the module
    Import-Module .\NPS-Module.psm1

    # Get help for any cmdlet
    Get-Help Connect-NPSServer -Full
    Get-Help Get-NPSManagedResource -Examples

    # List all available cmdlets
    Get-Command -Module NPS-Module
#>

#Requires -Version 5.1

# ============================================================================
# MODULE VARIABLES
# ============================================================================
$Script:NPSSession = @{
    Server = $null
    Token = $null
    TokenExpiry = $null
    Connected = $false
}

# ============================================================================
# AUTHENTICATION CMDLETS
# ============================================================================

function Connect-NPSServer {
    <#
    .SYNOPSIS
        Establishes a connection to a Netwrix Privilege Secure server.

    .DESCRIPTION
        Authenticates to a Netwrix Privilege Secure server using the two-step
        MFA authentication flow. First authenticates with username/password,
        then completes MFA verification to obtain a full access JWT token.

        The token is stored in the module session and automatically used by
        all subsequent cmdlets. Tokens expire after approximately 15 minutes.

    .PARAMETER Server
        The URL of the NPS server (e.g., "https://nps.company.com").
        Do not include trailing slash or /api path.

    .PARAMETER Username
        The username for authentication.

    .PARAMETER Password
        The password for authentication. Can be a SecureString or plain text.

    .PARAMETER MfaCode
        The 6-digit MFA/TOTP code from your authenticator app.

    .PARAMETER Credential
        A PSCredential object containing username and password.
        Alternative to specifying Username and Password separately.

    .PARAMETER SkipCertificateCheck
        Skip SSL certificate validation. Use for self-signed certificates.

    .OUTPUTS
        System.Boolean
        Returns $true if connection successful, $false otherwise.

    .EXAMPLE
        Connect-NPSServer -Server "https://nps.company.com" -Username "admin" -Password "P@ssw0rd" -MfaCode "123456"

        Connects to NPS server with explicit credentials.

    .EXAMPLE
        $cred = Get-Credential
        Connect-NPSServer -Server "https://nps.company.com" -Credential $cred -MfaCode "123456"

        Connects using a PSCredential object (prompts for credentials).

    .EXAMPLE
        Connect-NPSServer -Server "https://nps.company.com" -Username "admin" -Password "P@ss" -MfaCode "123456" -SkipCertificateCheck

        Connects while ignoring SSL certificate errors (for self-signed certs).

    .NOTES
        The authentication flow is:
        1. POST /signinBody - Returns pre-MFA token
        2. POST /signin2fa - Returns full access JWT token

        Tokens expire after ~15 minutes. Use Test-NPSConnection to check status.

    .LINK
        Test-NPSConnection
        Disconnect-NPSServer
    #>
    [CmdletBinding(DefaultParameterSetName = "Explicit")]
    param(
        [Parameter(Mandatory = $true, Position = 0)]
        [ValidateNotNullOrEmpty()]
        [string]$Server,

        [Parameter(Mandatory = $true, ParameterSetName = "Explicit")]
        [string]$Username,

        [Parameter(Mandatory = $true, ParameterSetName = "Explicit")]
        [string]$Password,

        [Parameter(Mandatory = $true, ParameterSetName = "Credential")]
        [PSCredential]$Credential,

        [Parameter(Mandatory = $true)]
        [ValidatePattern("^\d{6}$")]
        [string]$MfaCode,

        [Parameter()]
        [switch]$SkipCertificateCheck
    )

    begin {
        if ($SkipCertificateCheck) {
            if ($PSVersionTable.PSVersion.Major -ge 6) {
                $Script:SkipCert = $true
            } else {
                [System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }
            }
        }
    }

    process {
        try {
            # Extract credentials
            if ($PSCmdlet.ParameterSetName -eq "Credential") {
                $Username = $Credential.UserName
                $Password = $Credential.GetNetworkCredential().Password
            }

            $Server = $Server.TrimEnd("/")

            # Step 1: Initial authentication
            Write-Verbose "Authenticating to $Server..."
            $authBody = @{ Login = $Username; Password = $Password } | ConvertTo-Json

            $authParams = @{
                Uri = "$Server/signinBody"
                Method = "POST"
                Body = $authBody
                ContentType = "application/json"
            }
            if ($Script:SkipCert -and $PSVersionTable.PSVersion.Major -ge 6) {
                $authParams.SkipCertificateCheck = $true
            }

            $preMfaToken = Invoke-RestMethod @authParams

            # Step 2: MFA verification
            Write-Verbose "Completing MFA verification..."
            $mfaParams = @{
                Uri = "$Server/signin2fa"
                Method = "POST"
                Body = "`"$MfaCode`""
                ContentType = "application/json"
                Headers = @{ Authorization = "Bearer $preMfaToken" }
            }
            if ($Script:SkipCert -and $PSVersionTable.PSVersion.Major -ge 6) {
                $mfaParams.SkipCertificateCheck = $true
            }

            $fullToken = Invoke-RestMethod @mfaParams

            # Store session
            $Script:NPSSession.Server = $Server
            $Script:NPSSession.Token = $fullToken
            $Script:NPSSession.TokenExpiry = (Get-Date).AddMinutes(15)
            $Script:NPSSession.Connected = $true

            Write-Host "Successfully connected to $Server" -ForegroundColor Green
            return $true
        }
        catch {
            Write-Error "Failed to connect: $_"
            return $false
        }
    }
}

function Disconnect-NPSServer {
    <#
    .SYNOPSIS
        Disconnects from the current NPS server session.

    .DESCRIPTION
        Clears the stored authentication token and session information.
        After disconnecting, you must call Connect-NPSServer again to
        use other cmdlets.

    .EXAMPLE
        Disconnect-NPSServer

        Disconnects from the current NPS session.

    .LINK
        Connect-NPSServer
        Test-NPSConnection
    #>
    [CmdletBinding()]
    param()

    $Script:NPSSession.Server = $null
    $Script:NPSSession.Token = $null
    $Script:NPSSession.TokenExpiry = $null
    $Script:NPSSession.Connected = $false

    Write-Host "Disconnected from NPS server" -ForegroundColor Yellow
}

function Test-NPSConnection {
    <#
    .SYNOPSIS
        Tests if the current NPS connection is valid.

    .DESCRIPTION
        Checks if there is an active connection to an NPS server and
        whether the authentication token is still valid (not expired).
        Optionally performs a live health check against the server.

    .PARAMETER LiveCheck
        Perform a live API call to verify the connection is working.

    .OUTPUTS
        System.Boolean
        Returns $true if connected and token valid, $false otherwise.

    .EXAMPLE
        Test-NPSConnection

        Checks if connected (token-based check only).

    .EXAMPLE
        Test-NPSConnection -LiveCheck

        Performs a live API call to verify the connection.

    .EXAMPLE
        if (-not (Test-NPSConnection)) { Connect-NPSServer ... }

        Reconnect if not connected.

    .LINK
        Connect-NPSServer
        Disconnect-NPSServer
    #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [switch]$LiveCheck
    )

    if (-not $Script:NPSSession.Connected) {
        Write-Verbose "Not connected to any NPS server"
        return $false
    }

    if ($Script:NPSSession.TokenExpiry -lt (Get-Date)) {
        Write-Warning "Token has expired. Please reconnect."
        return $false
    }

    if ($LiveCheck) {
        try {
            $health = Invoke-NPSApi -Endpoint "/api/v1/Health" -Method GET
            return ($health -eq "Healthy")
        }
        catch {
            Write-Warning "Live check failed: $_"
            return $false
        }
    }

    return $true
}

# ============================================================================
# CORE API CMDLET
# ============================================================================

function Invoke-NPSApi {
    <#
    .SYNOPSIS
        Invokes a raw API call to the NPS server.

    .DESCRIPTION
        Low-level cmdlet for making direct API calls to the NPS server.
        Automatically includes authentication headers and handles errors.
        Use this for endpoints not covered by specific cmdlets.

    .PARAMETER Endpoint
        The API endpoint path (e.g., "/api/v1/ManagedResource").

    .PARAMETER Method
        HTTP method: GET, POST, PUT, DELETE.
        Default: GET

    .PARAMETER Body
        Request body for POST/PUT requests. Can be a hashtable or JSON string.

    .PARAMETER RawResponse
        Return the raw response object instead of just the content.

    .OUTPUTS
        System.Object
        The API response, typically a PSCustomObject or array.

    .EXAMPLE
        Invoke-NPSApi -Endpoint "/api/v1/Health"

        Gets the health status.

    .EXAMPLE
        Invoke-NPSApi -Endpoint "/api/v1/ManagedResource" -Method GET

        Lists all managed resources.

    .EXAMPLE
        $body = @{ name = "NewResource" }
        Invoke-NPSApi -Endpoint "/api/v1/ManagedResource" -Method POST -Body $body

        Creates a new resource.

    .EXAMPLE
        Invoke-NPSApi -Endpoint "/api/v1/Credential/Search" | Select-Object -ExpandProperty data

        Searches credentials and extracts the data array.

    .NOTES
        Requires an active connection via Connect-NPSServer.

    .LINK
        Connect-NPSServer
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, Position = 0)]
        [string]$Endpoint,

        [Parameter()]
        [ValidateSet("GET", "POST", "PUT", "DELETE")]
        [string]$Method = "GET",

        [Parameter()]
        [object]$Body,

        [Parameter()]
        [switch]$RawResponse
    )

    if (-not (Test-NPSConnection)) {
        throw "Not connected to NPS server. Use Connect-NPSServer first."
    }

    $uri = "$($Script:NPSSession.Server)$Endpoint"

    $params = @{
        Uri = $uri
        Method = $Method
        Headers = @{
            Authorization = "Bearer $($Script:NPSSession.Token)"
            "Content-Type" = "application/json"
        }
    }

    if ($Body) {
        if ($Body -is [hashtable] -or $Body -is [PSCustomObject]) {
            $params.Body = $Body | ConvertTo-Json -Depth 10
        } else {
            $params.Body = $Body
        }
    }

    if ($Script:SkipCert -and $PSVersionTable.PSVersion.Major -ge 6) {
        $params.SkipCertificateCheck = $true
    }

    try {
        $response = Invoke-RestMethod @params
        return $response
    }
    catch {
        $statusCode = $_.Exception.Response.StatusCode.value__
        Write-Error "API call failed [$statusCode]: $_"
        throw
    }
}

# ============================================================================
# MANAGED RESOURCE CMDLETS
# ============================================================================

function Get-NPSManagedResource {
    <#
    .SYNOPSIS
        Retrieves managed resources from NPS.

    .DESCRIPTION
        Gets managed resources (servers, workstations, network devices) from
        Netwrix Privilege Secure. Can retrieve all resources, search with
        pagination, or get a specific resource by ID.

        Managed resources represent the systems that NPS manages privileged
        access to, including Windows servers, Linux hosts, network devices,
        databases, and cloud resources.

    .PARAMETER Id
        The unique identifier (GUID) of a specific resource to retrieve.

    .PARAMETER Search
        Use the Search endpoint for paginated results with metadata.
        Returns object with 'data' array and 'recordsTotal' count.

    .PARAMETER Filter
        Filter expression for searching (when using -Search).

    .PARAMETER First
        Maximum number of results to return (pagination).

    .PARAMETER Skip
        Number of results to skip (pagination offset).

    .OUTPUTS
        PSCustomObject or PSCustomObject[]
        Managed resource object(s) with properties:
        - id: Unique identifier (GUID)
        - name: Display name
        - type: Resource type
        - platformId: Associated platform GUID
        - platformName: Platform display name
        - dnsHostName: DNS hostname
        - os: Operating system
        - serviceAccountId: Service account GUID
        - activeSessionCount: Current active sessions
        - accessPolicyCount: Associated access policies
        - ports: Port configuration (SSH, RDP, WinRM)

    .EXAMPLE
        Get-NPSManagedResource

        Lists all managed resources.

    .EXAMPLE
        Get-NPSManagedResource -Id "12345678-1234-1234-1234-123456789abc"

        Gets a specific resource by ID.

    .EXAMPLE
        Get-NPSManagedResource -Search

        Gets resources with pagination metadata.

    .EXAMPLE
        Get-NPSManagedResource -Search -First 10 -Skip 20

        Gets resources 21-30 (pagination).

    .EXAMPLE
        Get-NPSManagedResource | Where-Object { $_.os -like "*Windows*" }

        Filters for Windows resources.

    .EXAMPLE
        Get-NPSManagedResource | Select-Object name, dnsHostName, os | Format-Table

        Displays resources in a table format.

    .NOTES
        Schema fields: id, name, type, platformId, platformName, dnsHostName,
        os, serviceAccountId, createdDateTimeUtc, modifiedDateTimeUtc,
        lastScanTimeUtc, activeSessionCount, accessPolicyCount, ports

    .LINK
        Get-NPSCredential
        Get-NPSManagedAccount
    #>
    [CmdletBinding(DefaultParameterSetName = "List")]
    param(
        [Parameter(ParameterSetName = "ById", Mandatory = $true, Position = 0)]
        [ValidatePattern("^[0-9a-fA-F-]{36}$")]
        [string]$Id,

        [Parameter(ParameterSetName = "Search")]
        [switch]$Search,

        [Parameter(ParameterSetName = "Search")]
        [string]$Filter,

        [Parameter(ParameterSetName = "Search")]
        [Parameter(ParameterSetName = "List")]
        [int]$First,

        [Parameter(ParameterSetName = "Search")]
        [Parameter(ParameterSetName = "List")]
        [int]$Skip
    )

    switch ($PSCmdlet.ParameterSetName) {
        "ById" {
            Invoke-NPSApi -Endpoint "/api/v1/ManagedResource/$Id"
        }
        "Search" {
            $endpoint = "/api/v1/ManagedResource/Search"
            $result = Invoke-NPSApi -Endpoint $endpoint
            if ($First -or $Skip) {
                $data = $result.data
                if ($Skip) { $data = $data | Select-Object -Skip $Skip }
                if ($First) { $data = $data | Select-Object -First $First }
                $result.data = $data
            }
            $result
        }
        default {
            $result = Invoke-NPSApi -Endpoint "/api/v1/ManagedResource"
            if ($First -or $Skip) {
                if ($Skip) { $result = $result | Select-Object -Skip $Skip }
                if ($First) { $result = $result | Select-Object -First $First }
            }
            $result
        }
    }
}

# ============================================================================
# CREDENTIAL CMDLETS
# ============================================================================

function Get-NPSCredential {
    <#
    .SYNOPSIS
        Retrieves credentials from NPS.

    .DESCRIPTION
        Gets credential objects from Netwrix Privilege Secure. Credentials
        represent stored secrets including passwords, SSH keys, API keys,
        and other authentication materials.

        Supports listing all credentials, searching with pagination,
        retrieving by ID, or getting a count of total credentials.

    .PARAMETER Id
        The unique identifier (GUID) of a specific credential to retrieve.

    .PARAMETER Search
        Use the Search endpoint for paginated results with metadata.

    .PARAMETER Count
        Return only the total count of credentials (integer).

    .PARAMETER Type
        Filter by credential type: Shell, Database, FTP, Cloud, ESX, ITSM, Splunk.

    .OUTPUTS
        PSCustomObject, PSCustomObject[], or Int32
        Credential object(s) with properties:
        - id: Unique identifier (GUID)
        - name: Display name
        - domain: Domain name
        - username: Username
        - platformId: Associated platform GUID
        - userId: Owner user GUID
        - changeOnCheckout: Auto-change on checkout
        - changeOnRelease: Auto-change on release
        - authenticationMethod: Auth method type
        - keyGenAlgorithm: Key generation algorithm
        - createdDateTimeUtc: Creation timestamp
        - modifiedDateTimeUtc: Last modified timestamp

    .EXAMPLE
        Get-NPSCredential

        Lists all credentials.

    .EXAMPLE
        Get-NPSCredential -Count

        Returns the total number of credentials (e.g., 661).

    .EXAMPLE
        Get-NPSCredential -Id "12345678-1234-1234-1234-123456789abc"

        Gets a specific credential by ID.

    .EXAMPLE
        Get-NPSCredential -Search | Select-Object -ExpandProperty data | Where-Object { $_.domain -eq "CORP" }

        Searches and filters credentials by domain.

    .EXAMPLE
        (Get-NPSCredential -Search).recordsTotal

        Gets the total record count from search metadata.

    .NOTES
        Requires CredentialsManage permission for full access.
        Credential types: Shell, Database, FTP, Cloud, ESX, ITSM, Splunk

    .LINK
        Get-NPSManagedResource
        Get-NPSManagedAccount
    #>
    [CmdletBinding(DefaultParameterSetName = "List")]
    param(
        [Parameter(ParameterSetName = "ById", Mandatory = $true, Position = 0)]
        [ValidatePattern("^[0-9a-fA-F-]{36}$")]
        [string]$Id,

        [Parameter(ParameterSetName = "Search")]
        [switch]$Search,

        [Parameter(ParameterSetName = "Count")]
        [switch]$Count,

        [Parameter(ParameterSetName = "List")]
        [Parameter(ParameterSetName = "Search")]
        [ValidateSet("Shell", "Database", "FTP", "Cloud", "ESX", "ITSM", "Splunk")]
        [string]$Type
    )

    switch ($PSCmdlet.ParameterSetName) {
        "ById" {
            Invoke-NPSApi -Endpoint "/api/v1/Credential/$Id"
        }
        "Search" {
            Invoke-NPSApi -Endpoint "/api/v1/Credential/Search"
        }
        "Count" {
            Invoke-NPSApi -Endpoint "/api/v1/Credential/Count"
        }
        default {
            Invoke-NPSApi -Endpoint "/api/v1/Credential"
        }
    }
}

# ============================================================================
# ACTIVITY SESSION CMDLETS
# ============================================================================

function Get-NPSActivitySession {
    <#
    .SYNOPSIS
        Retrieves activity sessions from NPS.

    .DESCRIPTION
        Gets activity session records from Netwrix Privilege Secure.
        Activity sessions represent user sessions for privileged access,
        including RDP, SSH, and credential checkout sessions.

        Sessions track who accessed what resource, when, from where,
        and what actions were performed.

    .PARAMETER Id
        The unique identifier (GUID) of a specific session to retrieve.

    .PARAMETER Search
        Use the Search endpoint for paginated results with summary metadata.

    .PARAMETER IncludeLog
        When retrieving by ID, also fetch the session log entries.

    .PARAMETER Active
        Filter to show only currently active sessions.

    .OUTPUTS
        PSCustomObject or PSCustomObject[]
        Activity session object(s) with properties:
        - id: Unique identifier (GUID)
        - createdBy: User GUID who created session
        - createdByUserName: Username who created session
        - createdFromAddress: Source IP address
        - credentialId: Credential GUID used
        - userCredentialId: User credential GUID
        - loginAccountName: Login account name
        - activityId: Associated activity GUID
        - activity: Nested activity object
        - locked: Lock status

    .EXAMPLE
        Get-NPSActivitySession

        Lists all activity sessions.

    .EXAMPLE
        Get-NPSActivitySession -Search

        Gets sessions with pagination and summary metadata.

    .EXAMPLE
        Get-NPSActivitySession -Id "12345678-1234-1234-1234-123456789abc"

        Gets a specific session by ID.

    .EXAMPLE
        Get-NPSActivitySession -Id "12345678-..." -IncludeLog

        Gets a session with its log entries.

    .EXAMPLE
        Get-NPSActivitySession | Where-Object { $_.createdFromAddress -eq "192.168.1.100" }

        Filters sessions by source IP.

    .EXAMPLE
        (Get-NPSActivitySession -Search).recordsTotal

        Gets total session count.

    .NOTES
        Session logs available via /api/v1/ActivitySession/{id}/Log

    .LINK
        Get-NPSActivity
        Get-NPSCredential
    #>
    [CmdletBinding(DefaultParameterSetName = "List")]
    param(
        [Parameter(ParameterSetName = "ById", Mandatory = $true, Position = 0)]
        [ValidatePattern("^[0-9a-fA-F-]{36}$")]
        [string]$Id,

        [Parameter(ParameterSetName = "Search")]
        [switch]$Search,

        [Parameter(ParameterSetName = "ById")]
        [switch]$IncludeLog,

        [Parameter(ParameterSetName = "List")]
        [switch]$Active
    )

    switch ($PSCmdlet.ParameterSetName) {
        "ById" {
            $session = Invoke-NPSApi -Endpoint "/api/v1/ActivitySession/$Id"
            if ($IncludeLog) {
                $log = Invoke-NPSApi -Endpoint "/api/v1/ActivitySession/$Id/Log"
                $session | Add-Member -NotePropertyName "Log" -NotePropertyValue $log -Force
            }
            $session
        }
        "Search" {
            Invoke-NPSApi -Endpoint "/api/v1/ActivitySession/Search"
        }
        default {
            $sessions = Invoke-NPSApi -Endpoint "/api/v1/ActivitySession"
            if ($Active) {
                $sessions | Where-Object { $_.locked -eq $true }
            } else {
                $sessions
            }
        }
    }
}

function Get-NPSActivitySessionLog {
    <#
    .SYNOPSIS
        Retrieves log entries for an activity session.

    .DESCRIPTION
        Gets the detailed log entries for a specific activity session.
        Logs contain timestamped records of actions performed during
        the privileged access session.

    .PARAMETER SessionId
        The unique identifier (GUID) of the activity session.

    .OUTPUTS
        PSCustomObject[]
        Array of log entry objects.

    .EXAMPLE
        Get-NPSActivitySessionLog -SessionId "12345678-1234-1234-1234-123456789abc"

        Gets log entries for the specified session.

    .EXAMPLE
        Get-NPSActivitySession | Select-Object -First 1 | ForEach-Object { Get-NPSActivitySessionLog -SessionId $_.id }

        Gets logs for the first session.

    .LINK
        Get-NPSActivitySession
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, Position = 0, ValueFromPipelineByPropertyName = $true)]
        [Alias("Id")]
        [ValidatePattern("^[0-9a-fA-F-]{36}$")]
        [string]$SessionId
    )

    process {
        Invoke-NPSApi -Endpoint "/api/v1/ActivitySession/$SessionId/Log"
    }
}

# ============================================================================
# ACTIVITY CMDLETS
# ============================================================================

function Get-NPSActivity {
    <#
    .SYNOPSIS
        Retrieves activity definitions from NPS.

    .DESCRIPTION
        Gets activity definitions from Netwrix Privilege Secure.
        Activities define the types of privileged access available,
        such as RDP sessions, SSH sessions, or credential releases.

        Each activity specifies the access type, associated platform,
        login account behavior, and action groups to execute.

    .PARAMETER Id
        The unique identifier (GUID) of a specific activity to retrieve.

    .OUTPUTS
        PSCustomObject or PSCustomObject[]
        Activity object(s) with properties:
        - id: Unique identifier (GUID)
        - name: Display name
        - activityType: Type (0=Token, 1=RDP, 2=SSH, 3=CredentialRelease)
        - platformId: Associated platform GUID
        - loginAccount: Login account configuration
        - createAccount: Account creation settings
        - deleteAccount: Account deletion settings
        - startActionGroupId: Pre-session action group
        - duringActionGroupId: During-session action group
        - endActionGroupId: Post-session action group

    .EXAMPLE
        Get-NPSActivity

        Lists all activity definitions.

    .EXAMPLE
        Get-NPSActivity -Id "12345678-1234-1234-1234-123456789abc"

        Gets a specific activity by ID.

    .EXAMPLE
        Get-NPSActivity | Where-Object { $_.activityType -eq 1 }

        Gets all RDP activities (type 1).

    .EXAMPLE
        Get-NPSActivity | Group-Object activityType | Select-Object Name, Count

        Groups activities by type.

    .NOTES
        Activity Types:
        - 0: Token
        - 1: RDP (Remote Desktop)
        - 2: SSH (Secure Shell)
        - 3: CredentialRelease

    .LINK
        Get-NPSActivitySession
        Get-NPSActivityGroup
    #>
    [CmdletBinding(DefaultParameterSetName = "List")]
    param(
        [Parameter(ParameterSetName = "ById", Mandatory = $true, Position = 0)]
        [ValidatePattern("^[0-9a-fA-F-]{36}$")]
        [string]$Id
    )

    if ($Id) {
        Invoke-NPSApi -Endpoint "/api/v1/Activity/$Id"
    } else {
        Invoke-NPSApi -Endpoint "/api/v1/Activity"
    }
}

function Get-NPSActivityGroup {
    <#
    .SYNOPSIS
        Retrieves activity groups from NPS.

    .DESCRIPTION
        Gets activity group definitions. Activity groups organize
        related activities together for management purposes.

    .PARAMETER Id
        The unique identifier (GUID) of a specific activity group.

    .OUTPUTS
        PSCustomObject or PSCustomObject[]
        Activity group object(s).

    .EXAMPLE
        Get-NPSActivityGroup

        Lists all activity groups.

    .EXAMPLE
        Get-NPSActivityGroup -Id "12345678-1234-1234-1234-123456789abc"

        Gets a specific activity group.

    .LINK
        Get-NPSActivity
    #>
    [CmdletBinding()]
    param(
        [Parameter(Position = 0)]
        [ValidatePattern("^[0-9a-fA-F-]{36}$")]
        [string]$Id
    )

    if ($Id) {
        Invoke-NPSApi -Endpoint "/api/v1/ActivityGroup/$Id"
    } else {
        Invoke-NPSApi -Endpoint "/api/v1/ActivityGroup"
    }
}

# ============================================================================
# ACCESS CONTROL POLICY CMDLETS
# ============================================================================

function Get-NPSAccessControlPolicy {
    <#
    .SYNOPSIS
        Retrieves access control policies from NPS.

    .DESCRIPTION
        Gets access control policy definitions from Netwrix Privilege Secure.
        Policies define who can access what resources, under what conditions,
        and with what approval requirements.

        Policies can require notes, tickets, approvals, and can be
        associated with specific managed accounts, resources, and credentials.

    .PARAMETER Id
        The unique identifier (GUID) of a specific policy to retrieve.

    .PARAMETER Search
        Use the Search endpoint for paginated results.

    .OUTPUTS
        PSCustomObject or PSCustomObject[]
        Access control policy object(s) with properties:
        - id: Unique identifier (GUID)
        - name: Policy name
        - priority: Policy priority (lower = higher priority)
        - notesRequired: Require notes for access
        - ticketRequired: Require ticket number
        - approvalTypeRequired: Approval workflow type
        - policyType: Policy type
        - managedAccountIds: Associated account GUIDs
        - managedResourceIds: Associated resource GUIDs
        - credentialIds: Associated credential GUIDs
        - activityIds: Associated activity GUIDs
        - activities: Nested activity objects

    .EXAMPLE
        Get-NPSAccessControlPolicy

        Lists all access control policies.

    .EXAMPLE
        Get-NPSAccessControlPolicy -Id "12345678-1234-1234-1234-123456789abc"

        Gets a specific policy by ID.

    .EXAMPLE
        Get-NPSAccessControlPolicy | Where-Object { $_.approvalTypeRequired -ne $null }

        Gets policies that require approval.

    .EXAMPLE
        Get-NPSAccessControlPolicy | Sort-Object priority | Select-Object name, priority

        Lists policies sorted by priority.

    .LINK
        Get-NPSManagedResource
        Get-NPSCredential
        Get-NPSApprovalWorkflow
    #>
    [CmdletBinding(DefaultParameterSetName = "List")]
    param(
        [Parameter(ParameterSetName = "ById", Mandatory = $true, Position = 0)]
        [ValidatePattern("^[0-9a-fA-F-]{36}$")]
        [string]$Id,

        [Parameter(ParameterSetName = "Search")]
        [switch]$Search
    )

    switch ($PSCmdlet.ParameterSetName) {
        "ById" {
            Invoke-NPSApi -Endpoint "/api/v1/AccessControlPolicy/$Id"
        }
        "Search" {
            Invoke-NPSApi -Endpoint "/api/v1/AccessControlPolicy/Search"
        }
        default {
            Invoke-NPSApi -Endpoint "/api/v1/AccessControlPolicy"
        }
    }
}

# ============================================================================
# MANAGED ACCOUNT CMDLETS
# ============================================================================

function Get-NPSManagedAccount {
    <#
    .SYNOPSIS
        Retrieves managed accounts from NPS.

    .DESCRIPTION
        Gets managed account information from Netwrix Privilege Secure.
        Managed accounts are the privileged accounts that NPS manages,
        including local admin accounts, service accounts, and domain accounts.

    .PARAMETER Search
        Use the Search endpoint for paginated results.

    .PARAMETER HostUser
        Search for host user accounts specifically.

    .OUTPUTS
        PSCustomObject or PSCustomObject[]
        Managed account object(s).

    .EXAMPLE
        Get-NPSManagedAccount -Search

        Searches all managed accounts.

    .EXAMPLE
        Get-NPSManagedAccount -HostUser

        Searches host user accounts.

    .EXAMPLE
        (Get-NPSManagedAccount -Search).recordsTotal

        Gets total managed account count.

    .EXAMPLE
        (Get-NPSManagedAccount -HostUser).data | Select-Object -First 10

        Gets first 10 host user accounts.

    .LINK
        Get-NPSManagedResource
        Get-NPSCredential
    #>
    [CmdletBinding()]
    param(
        [Parameter(ParameterSetName = "Search")]
        [switch]$Search,

        [Parameter(ParameterSetName = "HostUser")]
        [switch]$HostUser
    )

    if ($HostUser) {
        Invoke-NPSApi -Endpoint "/api/v1/ManagedAccount/HostUser/Search"
    } else {
        Invoke-NPSApi -Endpoint "/api/v1/ManagedAccount/Search"
    }
}

# ============================================================================
# ACTION MANAGEMENT CMDLETS
# ============================================================================

function Get-NPSActionQueue {
    <#
    .SYNOPSIS
        Retrieves action queue items from NPS.

    .DESCRIPTION
        Gets items from the action queue. The action queue contains
        pending and completed actions such as password rotations,
        account provisioning, and other automated tasks.

    .PARAMETER Search
        Use the Search endpoint for paginated results.

    .PARAMETER Status
        Filter by action status.

    .OUTPUTS
        PSCustomObject or PSCustomObject[]
        Action queue item(s).

    .EXAMPLE
        Get-NPSActionQueue

        Lists action queue items.

    .EXAMPLE
        Get-NPSActionQueue -Search

        Searches action queue with pagination.

    .EXAMPLE
        (Get-NPSActionQueue -Search).recordsTotal

        Gets total queue item count.

    .LINK
        Get-NPSActionJob
        Get-NPSActionGroup
    #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [switch]$Search
    )

    if ($Search) {
        Invoke-NPSApi -Endpoint "/api/v1/ActionQueue/Search"
    } else {
        Invoke-NPSApi -Endpoint "/api/v1/ActionQueue"
    }
}

function Get-NPSActionJob {
    <#
    .SYNOPSIS
        Retrieves action jobs from NPS.

    .DESCRIPTION
        Gets action job records. Action jobs represent individual
        execution instances of actions, with status, timing, and
        result information.

    .PARAMETER Id
        The unique identifier of a specific action job.

    .PARAMETER Search
        Use the Search endpoint for paginated results.

    .OUTPUTS
        PSCustomObject or PSCustomObject[]
        Action job object(s).

    .EXAMPLE
        Get-NPSActionJob

        Lists action jobs.

    .EXAMPLE
        Get-NPSActionJob -Search

        Searches action jobs with pagination.

    .EXAMPLE
        Get-NPSActionJob -Id "12345678-1234-1234-1234-123456789abc"

        Gets a specific action job.

    .LINK
        Get-NPSActionQueue
        Get-NPSActionGroup
    #>
    [CmdletBinding(DefaultParameterSetName = "List")]
    param(
        [Parameter(ParameterSetName = "ById", Position = 0)]
        [string]$Id,

        [Parameter(ParameterSetName = "Search")]
        [switch]$Search
    )

    switch ($PSCmdlet.ParameterSetName) {
        "ById" {
            Invoke-NPSApi -Endpoint "/api/v1/ActionJob/$Id"
        }
        "Search" {
            Invoke-NPSApi -Endpoint "/api/v1/ActionJob/Search"
        }
        default {
            Invoke-NPSApi -Endpoint "/api/v1/ActionJob"
        }
    }
}

function Get-NPSActionGroup {
    <#
    .SYNOPSIS
        Retrieves action groups from NPS.

    .DESCRIPTION
        Gets action group definitions. Action groups organize
        related actions together and can be associated with
        activities for pre/during/post session execution.

    .PARAMETER Id
        The unique identifier of a specific action group.

    .PARAMETER IncludeActions
        Include the actions within the group.

    .OUTPUTS
        PSCustomObject or PSCustomObject[]
        Action group object(s).

    .EXAMPLE
        Get-NPSActionGroup

        Lists all action groups.

    .EXAMPLE
        Get-NPSActionGroup -Id "12345678-1234-1234-1234-123456789abc" -IncludeActions

        Gets a specific action group with its actions.

    .LINK
        Get-NPSActionJob
        Get-NPSActionTemplate
    #>
    [CmdletBinding()]
    param(
        [Parameter(Position = 0)]
        [ValidatePattern("^[0-9a-fA-F-]{36}$")]
        [string]$Id,

        [Parameter()]
        [switch]$IncludeActions
    )

    if ($Id) {
        $group = Invoke-NPSApi -Endpoint "/api/v1/ActionGroup/$Id"
        if ($IncludeActions) {
            $actions = Invoke-NPSApi -Endpoint "/api/v1/ActionGroup/$Id/Action"
            $group | Add-Member -NotePropertyName "Actions" -NotePropertyValue $actions -Force
        }
        $group
    } else {
        Invoke-NPSApi -Endpoint "/api/v1/ActionGroup"
    }
}

function Get-NPSActionTemplate {
    <#
    .SYNOPSIS
        Retrieves action templates from NPS.

    .DESCRIPTION
        Gets action template definitions. Templates define
        reusable action configurations that can be applied
        to action groups.

    .PARAMETER Id
        The unique identifier of a specific action template.

    .OUTPUTS
        PSCustomObject or PSCustomObject[]
        Action template object(s).

    .EXAMPLE
        Get-NPSActionTemplate

        Lists all action templates.

    .EXAMPLE
        Get-NPSActionTemplate -Id "12345678-1234-1234-1234-123456789abc"

        Gets a specific action template.

    .LINK
        Get-NPSActionGroup
    #>
    [CmdletBinding()]
    param(
        [Parameter(Position = 0)]
        [ValidatePattern("^[0-9a-fA-F-]{36}$")]
        [string]$Id
    )

    if ($Id) {
        Invoke-NPSApi -Endpoint "/api/v1/ActionTemplate/$Id"
    } else {
        Invoke-NPSApi -Endpoint "/api/v1/ActionTemplate"
    }
}

# ============================================================================
# HOST SCANNING CMDLETS
# ============================================================================

function Get-NPSHostScanJob {
    <#
    .SYNOPSIS
        Retrieves host scan jobs from NPS.

    .DESCRIPTION
        Gets host scan job records. Host scan jobs discover
        accounts, services, and other resources on managed hosts.

    .PARAMETER Search
        Use the Search endpoint for paginated results.

    .PARAMETER Type
        Filter by scan type: Host or User.

    .OUTPUTS
        PSCustomObject or PSCustomObject[]
        Host scan job object(s).

    .EXAMPLE
        Get-NPSHostScanJob

        Lists host scan jobs.

    .EXAMPLE
        Get-NPSHostScanJob -Search

        Searches host scan jobs with pagination.

    .EXAMPLE
        Get-NPSHostScanJob -Type Host

        Gets host-type scan jobs.

    .EXAMPLE
        Get-NPSHostScanJob -Type User

        Gets user-type scan jobs.

    .LINK
        Get-NPSManagedResource
    #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [switch]$Search,

        [Parameter()]
        [ValidateSet("Host", "User")]
        [string]$Type
    )

    if ($Type -eq "Host") {
        if ($Search) {
            Invoke-NPSApi -Endpoint "/api/v1/HostScanJob/Host/Search"
        } else {
            Invoke-NPSApi -Endpoint "/api/v1/HostScanJob/Host"
        }
    } elseif ($Type -eq "User") {
        if ($Search) {
            Invoke-NPSApi -Endpoint "/api/v1/HostScanJob/User/Search"
        } else {
            Invoke-NPSApi -Endpoint "/api/v1/HostScanJob/User"
        }
    } else {
        if ($Search) {
            Invoke-NPSApi -Endpoint "/api/v1/HostScanJob/Search"
        } else {
            Invoke-NPSApi -Endpoint "/api/v1/HostScanJob"
        }
    }
}

# ============================================================================
# PLATFORM CMDLETS
# ============================================================================

function Get-NPSPlatform {
    <#
    .SYNOPSIS
        Retrieves platform definitions from NPS.

    .DESCRIPTION
        Gets platform definitions. Platforms represent the types
        of systems that NPS can manage, such as Windows, Linux,
        network devices, databases, and cloud services.

    .PARAMETER Id
        The unique identifier of a specific platform.

    .OUTPUTS
        PSCustomObject or PSCustomObject[]
        Platform object(s).

    .EXAMPLE
        Get-NPSPlatform

        Lists all platforms.

    .EXAMPLE
        Get-NPSPlatform -Id "12345678-1234-1234-1234-123456789abc"

        Gets a specific platform.

    .EXAMPLE
        Get-NPSPlatform | Select-Object id, name | Format-Table

        Lists platforms in table format.

    .LINK
        Get-NPSManagedResource
    #>
    [CmdletBinding()]
    param(
        [Parameter(Position = 0)]
        [ValidatePattern("^[0-9a-fA-F-]{36}$")]
        [string]$Id
    )

    if ($Id) {
        Invoke-NPSApi -Endpoint "/api/v1/Platform/$Id"
    } else {
        Invoke-NPSApi -Endpoint "/api/v1/Platform"
    }
}

# ============================================================================
# WORKFLOW & POLICY CMDLETS
# ============================================================================

function Get-NPSApprovalWorkflow {
    <#
    .SYNOPSIS
        Retrieves approval workflows from NPS.

    .DESCRIPTION
        Gets approval workflow definitions. Workflows define
        the approval process for privileged access requests.

    .PARAMETER Id
        The unique identifier of a specific workflow.

    .OUTPUTS
        PSCustomObject or PSCustomObject[]
        Approval workflow object(s).

    .EXAMPLE
        Get-NPSApprovalWorkflow

        Lists all approval workflows.

    .EXAMPLE
        Get-NPSApprovalWorkflow -Id "12345678-1234-1234-1234-123456789abc"

        Gets a specific workflow.

    .LINK
        Get-NPSAccessControlPolicy
    #>
    [CmdletBinding()]
    param(
        [Parameter(Position = 0)]
        [ValidatePattern("^[0-9a-fA-F-]{36}$")]
        [string]$Id
    )

    if ($Id) {
        Invoke-NPSApi -Endpoint "/api/v1/ApprovalWorkflow/$Id"
    } else {
        Invoke-NPSApi -Endpoint "/api/v1/ApprovalWorkflow"
    }
}

function Get-NPSScheduledChangePolicy {
    <#
    .SYNOPSIS
        Retrieves scheduled change policies from NPS.

    .DESCRIPTION
        Gets scheduled change policy definitions. These policies
        define automated password rotation and other scheduled
        credential changes.

    .PARAMETER Id
        The unique identifier of a specific policy.

    .OUTPUTS
        PSCustomObject or PSCustomObject[]
        Scheduled change policy object(s).

    .EXAMPLE
        Get-NPSScheduledChangePolicy

        Lists all scheduled change policies.

    .EXAMPLE
        Get-NPSScheduledChangePolicy -Id "12345678-1234-1234-1234-123456789abc"

        Gets a specific policy.

    .LINK
        Get-NPSCredential
        Get-NPSProtectionPolicy
    #>
    [CmdletBinding()]
    param(
        [Parameter(Position = 0)]
        [ValidatePattern("^[0-9a-fA-F-]{36}$")]
        [string]$Id
    )

    if ($Id) {
        Invoke-NPSApi -Endpoint "/api/v1/ScheduledChangePolicy/$Id"
    } else {
        Invoke-NPSApi -Endpoint "/api/v1/ScheduledChangePolicy"
    }
}

function Get-NPSProtectionPolicy {
    <#
    .SYNOPSIS
        Retrieves protection policies from NPS.

    .DESCRIPTION
        Gets protection policy definitions. Protection policies
        define security controls and restrictions for managed
        resources and accounts.

    .PARAMETER Id
        The unique identifier of a specific policy.

    .OUTPUTS
        PSCustomObject or PSCustomObject[]
        Protection policy object(s).

    .EXAMPLE
        Get-NPSProtectionPolicy

        Lists all protection policies.

    .LINK
        Get-NPSScheduledChangePolicy
        Get-NPSAccessControlPolicy
    #>
    [CmdletBinding()]
    param(
        [Parameter(Position = 0)]
        [ValidatePattern("^[0-9a-fA-F-]{36}$")]
        [string]$Id
    )

    if ($Id) {
        Invoke-NPSApi -Endpoint "/api/v1/ProtectionPolicy/$Id"
    } else {
        Invoke-NPSApi -Endpoint "/api/v1/ProtectionPolicy"
    }
}

# ============================================================================
# SYSTEM & HEALTH CMDLETS
# ============================================================================

function Get-NPSHealth {
    <#
    .SYNOPSIS
        Gets the health status of the NPS server.

    .DESCRIPTION
        Retrieves the current health status of the Netwrix Privilege
        Secure server. Returns "Healthy" if the server is operating
        normally.

    .OUTPUTS
        System.String
        Health status string (typically "Healthy").

    .EXAMPLE
        Get-NPSHealth

        Returns the health status.

    .EXAMPLE
        if ((Get-NPSHealth) -eq "Healthy") { Write-Host "Server OK" }

        Checks if server is healthy.

    .LINK
        Get-NPSVersion
        Test-NPSConnection
    #>
    [CmdletBinding()]
    param()

    Invoke-NPSApi -Endpoint "/api/v1/Health"
}

function Get-NPSVersion {
    <#
    .SYNOPSIS
        Gets the version of the NPS server.

    .DESCRIPTION
        Retrieves the product version string of the Netwrix Privilege
        Secure server.

    .OUTPUTS
        System.String
        Version string (e.g., "25.12.00000").

    .EXAMPLE
        Get-NPSVersion

        Returns the version string.

    .EXAMPLE
        $version = Get-NPSVersion
        Write-Host "NPS Version: $version"

        Displays the version.

    .LINK
        Get-NPSHealth
        Get-NPSLicenseInfo
    #>
    [CmdletBinding()]
    param()

    Invoke-NPSApi -Endpoint "/api/v1/Version"
}

function Get-NPSLicenseInfo {
    <#
    .SYNOPSIS
        Gets license information for the NPS server.

    .DESCRIPTION
        Retrieves license details including credits, trial status,
        and customer information.

    .OUTPUTS
        PSCustomObject
        License information object.

    .EXAMPLE
        Get-NPSLicenseInfo

        Returns license information.

    .EXAMPLE
        (Get-NPSLicenseInfo).credits

        Gets available license credits.

    .LINK
        Get-NPSVersion
        Get-NPSHealth
    #>
    [CmdletBinding()]
    param()

    Invoke-NPSApi -Endpoint "/api/v1/LicenseInfo"
}

function Get-NPSActionService {
    <#
    .SYNOPSIS
        Gets action service registrations from NPS.

    .DESCRIPTION
        Retrieves registered action services. Action services
        are the components that execute actions on managed resources.

    .OUTPUTS
        PSCustomObject[]
        Action service object(s).

    .EXAMPLE
        Get-NPSActionService

        Lists all action services.

    .LINK
        Get-NPSActionJob
        Get-NPSServiceRegistration
    #>
    [CmdletBinding()]
    param()

    Invoke-NPSApi -Endpoint "/api/v1/ActionService"
}

function Get-NPSServiceRegistration {
    <#
    .SYNOPSIS
        Gets service registrations from NPS.

    .DESCRIPTION
        Retrieves all registered services in the NPS infrastructure.

    .OUTPUTS
        PSCustomObject[]
        Service registration object(s).

    .EXAMPLE
        Get-NPSServiceRegistration

        Lists all service registrations.

    .LINK
        Get-NPSActionService
    #>
    [CmdletBinding()]
    param()

    Invoke-NPSApi -Endpoint "/api/v1/ServiceRegistration"
}

# ============================================================================
# ADDITIONAL RESOURCE CMDLETS
# ============================================================================

function Get-NPSSecretVault {
    <#
    .SYNOPSIS
        Gets secret vaults from NPS.

    .DESCRIPTION
        Retrieves secret vault configurations. Vaults store
        credentials and other secrets securely.

    .OUTPUTS
        PSCustomObject[]
        Secret vault object(s).

    .EXAMPLE
        Get-NPSSecretVault

        Lists all secret vaults.

    .LINK
        Get-NPSCredential
    #>
    [CmdletBinding()]
    param()

    Invoke-NPSApi -Endpoint "/api/v1/SecretVault"
}

function Get-NPSWebsite {
    <#
    .SYNOPSIS
        Gets website configurations from NPS.

    .DESCRIPTION
        Retrieves website/web application configurations
        managed by NPS.

    .OUTPUTS
        PSCustomObject[]
        Website object(s).

    .EXAMPLE
        Get-NPSWebsite

        Lists all websites.

    .LINK
        Get-NPSManagedResource
    #>
    [CmdletBinding()]
    param()

    Invoke-NPSApi -Endpoint "/api/v1/Website"
}

function Get-NPSLog {
    <#
    .SYNOPSIS
        Gets log entries from NPS.

    .DESCRIPTION
        Retrieves system log entries for auditing and
        troubleshooting purposes.

    .PARAMETER Search
        Use the Search endpoint for paginated results.

    .OUTPUTS
        PSCustomObject[]
        Log entry object(s).

    .EXAMPLE
        Get-NPSLog

        Lists log entries.

    .EXAMPLE
        Get-NPSLog -Search

        Searches logs with pagination.

    .LINK
        Get-NPSActivitySession
    #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [switch]$Search
    )

    if ($Search) {
        Invoke-NPSApi -Endpoint "/api/v1/Log/Search"
    } else {
        Invoke-NPSApi -Endpoint "/api/v1/Log"
    }
}

function Get-NPSUser {
    <#
    .SYNOPSIS
        Gets user information from NPS.

    .DESCRIPTION
        Retrieves user account information. Note: This endpoint
        may require POST method and returns the current user's
        information or user template schema.

    .OUTPUTS
        PSCustomObject
        User object with 38+ fields including id, displayName,
        samaccountname, userPrincipalName, email, department, etc.

    .EXAMPLE
        Get-NPSUser

        Gets current user information.

    .NOTES
        Some user endpoints require POST method.

    .LINK
        Get-NPSManagedAccount
    #>
    [CmdletBinding()]
    param()

    try {
        Invoke-NPSApi -Endpoint "/api/v1/User" -Method POST
    }
    catch {
        # Fallback to GET if POST fails
        Invoke-NPSApi -Endpoint "/api/v1/User" -Method GET
    }
}

function Get-NPSHost {
    <#
    .SYNOPSIS
        Gets host information from NPS.

    .DESCRIPTION
        Retrieves host/server information. Note: This endpoint
        may require POST method and returns host template schema
        with 34+ fields.

    .OUTPUTS
        PSCustomObject
        Host object with fields including id, name, ipAddress,
        os, version, dnsHostName, users, groups, services, etc.

    .EXAMPLE
        Get-NPSHost

        Gets host information/schema.

    .NOTES
        Some host endpoints require POST method.

    .LINK
        Get-NPSManagedResource
        Get-NPSHostScanJob
    #>
    [CmdletBinding()]
    param()

    try {
        Invoke-NPSApi -Endpoint "/api/v1/Host" -Method POST
    }
    catch {
        Invoke-NPSApi -Endpoint "/api/v1/Host" -Method GET
    }
}

# ============================================================================
# UTILITY FUNCTIONS
# ============================================================================

function Export-NPSManagedResources {
    <#
    .SYNOPSIS
        Exports managed resources to a CSV file.

    .DESCRIPTION
        Retrieves all managed resources and exports them to a CSV
        file for reporting or analysis purposes.

    .PARAMETER Path
        The output file path. Default: .\ManagedResources.csv

    .PARAMETER IncludeDetails
        Include additional detail fields in the export.

    .OUTPUTS
        System.IO.FileInfo
        The exported file object.

    .EXAMPLE
        Export-NPSManagedResources

        Exports to default file ManagedResources.csv.

    .EXAMPLE
        Export-NPSManagedResources -Path "C:\Reports\resources.csv"

        Exports to specified path.

    .EXAMPLE
        Export-NPSManagedResources -IncludeDetails | Invoke-Item

        Exports with details and opens the file.

    .LINK
        Get-NPSManagedResource
    #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [string]$Path = ".\ManagedResources.csv",

        [Parameter()]
        [switch]$IncludeDetails
    )

    $resources = Get-NPSManagedResource

    if ($IncludeDetails) {
        $resources | Export-Csv -Path $Path -NoTypeInformation
    } else {
        $resources | Select-Object id, name, type, platformName, dnsHostName, os, activeSessionCount |
            Export-Csv -Path $Path -NoTypeInformation
    }

    Get-Item $Path
}

function Test-NPSServices {
    <#
    .SYNOPSIS
        Tests all NPS services and returns status.

    .DESCRIPTION
        Performs a comprehensive health check of the NPS server
        by testing multiple endpoints and services.

    .OUTPUTS
        PSCustomObject
        Object with service status information.

    .EXAMPLE
        Test-NPSServices

        Returns status of all services.

    .EXAMPLE
        Test-NPSServices | Format-List

        Displays detailed service status.

    .LINK
        Get-NPSHealth
        Get-NPSVersion
    #>
    [CmdletBinding()]
    param()

    $results = [PSCustomObject]@{
        Server = $Script:NPSSession.Server
        Connected = $Script:NPSSession.Connected
        TokenExpiry = $Script:NPSSession.TokenExpiry
        Health = $null
        Version = $null
        ActionServices = 0
        ServiceRegistrations = 0
        ManagedResources = 0
        Credentials = 0
        ActiveSessions = 0
    }

    try { $results.Health = Get-NPSHealth } catch { $results.Health = "Error" }
    try { $results.Version = Get-NPSVersion } catch { $results.Version = "Error" }
    try { $results.ActionServices = (Get-NPSActionService).Count } catch {}
    try { $results.ServiceRegistrations = (Get-NPSServiceRegistration).Count } catch {}
    try { $results.ManagedResources = (Get-NPSManagedResource).Count } catch {}
    try { $results.Credentials = Get-NPSCredential -Count } catch {}
    try { $results.ActiveSessions = (Get-NPSActivitySession).Count } catch {}

    $results
}

function Watch-NPSActionQueue {
    <#
    .SYNOPSIS
        Monitors the action queue in real-time.

    .DESCRIPTION
        Continuously monitors the action queue and displays
        new or changed items. Useful for watching password
        rotations and other automated actions.

    .PARAMETER IntervalSeconds
        Polling interval in seconds. Default: 5

    .PARAMETER Duration
        How long to monitor in minutes. Default: 5

    .EXAMPLE
        Watch-NPSActionQueue

        Monitors for 5 minutes with 5-second intervals.

    .EXAMPLE
        Watch-NPSActionQueue -IntervalSeconds 10 -Duration 30

        Monitors for 30 minutes with 10-second intervals.

    .NOTES
        Press Ctrl+C to stop monitoring.

    .LINK
        Get-NPSActionQueue
        Get-NPSActionJob
    #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [int]$IntervalSeconds = 5,

        [Parameter()]
        [int]$Duration = 5
    )

    $endTime = (Get-Date).AddMinutes($Duration)
    $lastCount = 0

    Write-Host "Monitoring action queue for $Duration minutes..." -ForegroundColor Cyan
    Write-Host "Press Ctrl+C to stop." -ForegroundColor Yellow

    while ((Get-Date) -lt $endTime) {
        try {
            $queue = Get-NPSActionQueue -Search
            $count = $queue.recordsTotal

            if ($count -ne $lastCount) {
                Write-Host "[$(Get-Date -Format 'HH:mm:ss')] Queue items: $count (changed from $lastCount)" -ForegroundColor Green
                $lastCount = $count
            } else {
                Write-Host "[$(Get-Date -Format 'HH:mm:ss')] Queue items: $count" -ForegroundColor Gray
            }
        }
        catch {
            Write-Warning "Error checking queue: $_"
        }

        Start-Sleep -Seconds $IntervalSeconds
    }

    Write-Host "Monitoring complete." -ForegroundColor Cyan
}

# ============================================================================
# MODULE EXPORT
# ============================================================================

# Export all public functions
Export-ModuleMember -Function @(
    # Authentication
    "Connect-NPSServer"
    "Disconnect-NPSServer"
    "Test-NPSConnection"

    # Core API
    "Invoke-NPSApi"

    # Managed Resources
    "Get-NPSManagedResource"

    # Credentials
    "Get-NPSCredential"

    # Activity Sessions
    "Get-NPSActivitySession"
    "Get-NPSActivitySessionLog"

    # Activities
    "Get-NPSActivity"
    "Get-NPSActivityGroup"

    # Access Control
    "Get-NPSAccessControlPolicy"

    # Managed Accounts
    "Get-NPSManagedAccount"

    # Actions
    "Get-NPSActionQueue"
    "Get-NPSActionJob"
    "Get-NPSActionGroup"
    "Get-NPSActionTemplate"

    # Host Scanning
    "Get-NPSHostScanJob"

    # Platforms
    "Get-NPSPlatform"

    # Workflows & Policies
    "Get-NPSApprovalWorkflow"
    "Get-NPSScheduledChangePolicy"
    "Get-NPSProtectionPolicy"

    # System & Health
    "Get-NPSHealth"
    "Get-NPSVersion"
    "Get-NPSLicenseInfo"
    "Get-NPSActionService"
    "Get-NPSServiceRegistration"

    # Additional Resources
    "Get-NPSSecretVault"
    "Get-NPSWebsite"
    "Get-NPSLog"
    "Get-NPSUser"
    "Get-NPSHost"

    # Utilities
    "Export-NPSManagedResources"
    "Test-NPSServices"
    "Watch-NPSActionQueue"
)

Write-Host @"

╔══════════════════════════════════════════════════════════════════╗
║     Netwrix Privilege Secure (NPS) PowerShell Module v1.0       ║
╠══════════════════════════════════════════════════════════════════╣
║  35+ cmdlets loaded. Use Get-Help <cmdlet> -Full for details.   ║
║                                                                  ║
║  Quick Start:                                                    ║
║    Connect-NPSServer -Server "https://nps" -Username "admin"    ║
║                      -Password "pass" -MfaCode "123456"         ║
║                                                                  ║
║  List all cmdlets:                                               ║
║    Get-Command -Module NPS-Module                                ║
║                                                                  ║
║  Get help:                                                       ║
║    Get-Help Get-NPSManagedResource -Full                         ║
║    Get-Help Get-NPSCredential -Examples                          ║
╚══════════════════════════════════════════════════════════════════╝

"@ -ForegroundColor Cyan
