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
    Server      = $null
    Token       = $null
    TokenExpiry = $null
    Connected   = $false
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
        [object]$Password,

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
            }
            else {
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
            elseif ($Password -is [System.Security.SecureString]) {
                $Password = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($Password))
            }

            $Server = $Server.TrimEnd("/")

            # Step 1: Initial authentication
            Write-Verbose "Authenticating to $Server..."
            $authBody = @{ Login = $Username; Password = $Password } | ConvertTo-Json

            $authParams = @{
                Uri         = "$Server/signinBody"
                Method      = "POST"
                Body        = $authBody
                ContentType = "application/json"
            }
            if ($Script:SkipCert -and $PSVersionTable.PSVersion.Major -ge 6) {
                $authParams.SkipCertificateCheck = $true
            }

            $preMfaToken = Invoke-RestMethod @authParams

            # Step 2: MFA verification
            Write-Verbose "Completing MFA verification..."
            $mfaParams = @{
                Uri         = "$Server/signin2fa"
                Method      = "POST"
                Body        = "`"$MfaCode`""
                ContentType = "application/json"
                Headers     = @{ Authorization = "Bearer $preMfaToken" }
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
# PRIVATE HELPER FUNCTIONS
# ============================================================================

function Invoke-NPSRest {
    <#
    .SYNOPSIS
        Internal helper for REST API calls (legacy compatibility).
    #>
    param(
        $Token,
        $Method = "GET",
        $Uri,
        $Body,
        $ContentType = "application/json",
        $Certificate,
        $WebSession,
        $SkipCertificateCheck
    )

    $params = @{
        Uri    = $Uri
        Method = $Method
    }

    if ($Token) { 
        $params.Headers = @{ Authorization = "Bearer $Token" } 
    }
    elseif ($Script:NPSSession.Token) {
        $params.Headers = @{ Authorization = "Bearer $($Script:NPSSession.Token)" }
    }

    if ($Body) { $params.Body = $Body }
    if ($ContentType) { $params.ContentType = $ContentType }
    if ($Certificate) { $params.Certificate = $Certificate }
    if ($WebSession) { $params.WebSession = $WebSession }
    if ($SkipCertificateCheck -or $Script:NPSSession.SkipCertificateCheck) { 
        $params.SkipCertificateCheck = $true 
    }

    return Invoke-RestMethod @params
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
        Uri     = $uri
        Method  = $Method
        Headers = @{
            Authorization  = "Bearer $($Script:NPSSession.Token)"
            "Content-Type" = "application/json"
        }
    }

    if ($Body) {
        if ($Body -is [hashtable] -or $Body -is [PSCustomObject]) {
            $params.Body = $Body | ConvertTo-Json -Depth 10
        }
        else {
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
            }
            else {
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
    }
    else {
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
    }
    else {
        Invoke-NPSApi -Endpoint "/api/v1/ActivityGroup"
    }
}

function Get-NPSConnectionProfile {
    <#
    .SYNOPSIS
        Retrieves connection profiles from NPS.

    .DESCRIPTION
        Gets connection profile definitions from Netwrix Privilege Secure.
        Connection profiles define how NPS connects to managed resources,
        including connection methods, ports, and authentication settings.

    .PARAMETER Id
        The unique identifier (GUID) of a specific connection profile.

    .OUTPUTS
        PSCustomObject or PSCustomObject[]
        Connection profile object(s).

    .EXAMPLE
        Get-NPSConnectionProfile

        Lists all connection profiles.

    .EXAMPLE
        Get-NPSConnectionProfile -Id "12345678-1234-1234-1234-123456789abc"

        Gets a specific connection profile by ID.

    .LINK
        Get-NPSManagedResource
        Get-NPSPlatform
    #>
    [CmdletBinding()]
    param(
        [Parameter(Position = 0)]
        [ValidatePattern("^[0-9a-fA-F-]{36}$")]
        [string]$Id
    )

    if ($Id) {
        Invoke-NPSApi -Endpoint "/api/v1/ConnectionProfile/$Id"
    }
    else {
        Invoke-NPSApi -Endpoint "/api/v1/ConnectionProfile"
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

    .NOTES
        The /api/v1/AccessControlPolicy/Search endpoint does not exist.
        Use PowerShell filtering on the list results instead.

    .LINK
        Get-NPSManagedResource
        Get-NPSCredential
        Get-NPSApprovalWorkflow
    #>
    [CmdletBinding(DefaultParameterSetName = "List")]
    param(
        [Parameter(ParameterSetName = "ById", Mandatory = $true, Position = 0)]
        [ValidatePattern("^[0-9a-fA-F-]{36}$")]
        [string]$Id
    )

    if ($Id) {
        Invoke-NPSApi -Endpoint "/api/v1/AccessControlPolicy/$Id"
    }
    else {
        Invoke-NPSApi -Endpoint "/api/v1/AccessControlPolicy"
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
    }
    else {
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
    }
    else {
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
    }
    else {
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
    }
    else {
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

    .PARAMETER Type
        Filter by scan type: Host or User.
        - Host: Returns host-type scan jobs
        - User: Returns user-type scan jobs
        If not specified, returns all scan jobs.

    .OUTPUTS
        PSCustomObject or PSCustomObject[]
        Host scan job object(s).

    .EXAMPLE
        Get-NPSHostScanJob

        Lists all host scan jobs.

    .EXAMPLE
        Get-NPSHostScanJob -Type Host

        Gets host-type scan jobs only.

    .EXAMPLE
        Get-NPSHostScanJob -Type User

        Gets user-type scan jobs only.

    .EXAMPLE
        Get-NPSHostScanJob | Where-Object { $_.status -eq "Completed" }

        Gets completed scan jobs using PowerShell filtering.

    .NOTES
        The /api/v1/HostScanJob/Search endpoint does not exist.
        Use PowerShell filtering on the list results instead.

    .LINK
        Get-NPSManagedResource
    #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [ValidateSet("Host", "User")]
        [string]$Type
    )

    switch ($Type) {
        "Host" {
            Invoke-NPSApi -Endpoint "/api/v1/HostScanJob/Host"
        }
        "User" {
            Invoke-NPSApi -Endpoint "/api/v1/HostScanJob/User"
        }
        default {
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
    }
    else {
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
    }
    else {
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
    }
    else {
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
    }
    else {
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
        Gets log files and log content from NPS.

    .DESCRIPTION
        Retrieves system log files for auditing and troubleshooting.
        Without parameters, lists all available log files.
        With -Name parameter, retrieves the content of a specific log file.

    .PARAMETER Name
        The name of a specific log file to retrieve content from.
        Use Get-NPSLog without parameters to see available log files.

    .PARAMETER Take
        Number of log lines to retrieve. Default is 100.
        Required when using -Name to get log content.

    .PARAMETER Skip
        Number of log lines to skip (for pagination). Default is 0.

    .OUTPUTS
        PSCustomObject[]
        Without -Name: Array of log file objects (id, name, length, lastWriteTime).
        With -Name: Object containing totalCount and lines array.

    .EXAMPLE
        Get-NPSLog

        Lists all available log files with their sizes and dates.

    .EXAMPLE
        Get-NPSLog -Name "PAM-Proxy20260120.log" -Take 50

        Gets the first 50 lines from the specified log file.

    .EXAMPLE
        Get-NPSLog -Name "PAM-Proxy20260120.log" -Skip 100 -Take 50

        Gets 50 lines starting from line 100 (pagination).

    .EXAMPLE
        Get-NPSLog | Where-Object { $_.length -gt 0 } | Select-Object name, length

        Lists log files that have content.

    .EXAMPLE
        $logs = Get-NPSLog -Name "PAM-ActionService20260119.log" -Take 1000
        $logs.lines | Where-Object { $_.statusString -eq "Error" }

        Gets log lines and filters for errors.

    .NOTES
        Log files are named with pattern: PAM-{ServiceName}{Date}.log
        Common services: Proxy, ActionService, EmailService, HostScanService

        The /api/v1/Log/Search endpoint does not work (returns 500 error).
        Use PowerShell filtering on the results instead.

    .LINK
        Get-NPSActivitySession
    #>
    [CmdletBinding()]
    param(
        [Parameter(Position = 0)]
        [string]$Name,

        [Parameter()]
        [int]$Take = 100,

        [Parameter()]
        [int]$Skip = 0
    )

    if ($Name) {
        # Get content of specific log file
        $endpoint = "/api/v1/Log/$Name"
        if ($Skip -gt 0) {
            $endpoint += "?skip=$Skip&take=$Take"
        }
        else {
            $endpoint += "?take=$Take"
        }
        Invoke-NPSApi -Endpoint $endpoint
    }
    else {
        # List all log files
        Invoke-NPSApi -Endpoint "/api/v1/Log"
    }
}

function Get-NPSUser {
    <#
    .SYNOPSIS
        Gets user information from NPS.

    .DESCRIPTION
        Retrieves user account information. The list endpoint requires
        POST method with a body. Individual users can be retrieved by ID.

    .PARAMETER Id
        Optional. Get a specific user by ID.

    .OUTPUTS
        PSCustomObject or PSCustomObject[]
        User object(s) with 38+ fields including id, displayName,
        samaccountname, userPrincipalName, email, department, etc.

    .EXAMPLE
        Get-NPSUser

        Lists all users.

    .EXAMPLE
        Get-NPSUser -Id "abc-123-def"

        Gets a specific user by ID.

    .NOTES
        The /api/v1/User endpoint requires POST with a body for listing.

    .LINK
        Get-NPSManagedAccount
    #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [string]$Id
    )

    if ($Id) {
        Invoke-NPSApi -Endpoint "/api/v1/User/$Id" -Method GET
    }
    else {
        # User endpoint requires POST with body
        $body = @{}
        Invoke-NPSApi -Endpoint "/api/v1/User" -Method POST -Body $body
    }
}

function Get-NPSHost {
    <#
    .SYNOPSIS
        Gets host information from NPS.

    .DESCRIPTION
        Retrieves host/server information. This endpoint uses POST
        method with a search body and returns host template schema
        with 34+ fields.

    .PARAMETER Id
        Optional. Get a specific host by ID.

    .OUTPUTS
        PSCustomObject
        Host object with fields including id, name, ipAddress,
        os, version, dnsHostName, users, groups, services, etc.

    .EXAMPLE
        Get-NPSHost

        Gets all hosts via search.

    .EXAMPLE
        Get-NPSHost -Id "abc-123"

        Gets a specific host by ID.

    .NOTES
        The Host endpoint requires POST method with a body.

    .LINK
        Get-NPSManagedResource
        Get-NPSHostScanJob
    #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [string]$Id
    )

    if ($Id) {
        Invoke-NPSApi -Endpoint "/api/v1/Host/$Id" -Method GET
    }
    else {
        # Host endpoint requires POST with body for search
        $body = @{}
        Invoke-NPSApi -Endpoint "/api/v1/Host" -Method POST -Body $body
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
    }
    else {
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
        Server               = $Script:NPSSession.Server
        Connected            = $Script:NPSSession.Connected
        TokenExpiry          = $Script:NPSSession.TokenExpiry
        Health               = $null
        Version              = $null
        ActionServices       = 0
        ServiceRegistrations = 0
        ManagedResources     = 0
        Credentials          = 0
        ActiveSessions       = 0
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
            }
            else {
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
    "Convert-NPSToken"
    "Get-NPSToken"
    "Get-NPSMfaToken"
    "Get-NPSUserToken"
    "Get-NPSAppUserToken"

    # Core API
    "Invoke-NPSApi"

    # Managed Resources
    "Get-NPSManagedResource"
    "Get-NPSManagedResourceSshFingerprint"
    "Set-NPSManagedResourceTrustThumbprint"

    # Credentials
    "Get-NPSCredential"
    "Get-NPSCredentialTypes"
    "Get-NPSCredentialSshCertificate"
    "Get-NPSAuthenticationMethodTypes"
    "Get-NPSCiscoEnablePassword"
    "Get-NPSCiscoEnablePasswordByCredential"

    # Activity Sessions
    "Get-NPSActivitySession"
    "Get-NPSActivitySessionLog"
    "Get-NPSActivitySessionPassword"
    "Get-NPSActivitySessionResource"
    "Get-NPSActivitySessionConfiguration"
    "Get-NPSActivitySessionCount"
    "Get-NPSActivitySessionSummary"
    "Start-NPSActivitySession"
    "Stop-NPSActivitySession"
    "Search-NPSActiveSession"
    "Search-NPSHistoricalSession"

    # Activities
    "Get-NPSActivity"
    "Get-NPSActivityGroup"

    # Access Control
    "Get-NPSAccessControlPolicy"
    "Get-NPSUserPolicy"

    # Managed Accounts
    "Get-NPSManagedAccount"

    # Actions
    "Get-NPSActionQueue"
    "Get-NPSActionJob"
    "Get-NPSActionGroup"
    "Get-NPSActionTemplate"
    "Get-NPSActionService"

    # Host Scanning
    "Get-NPSHostScanJob"
    "Get-NPSHost"

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
    "Get-NPSSettings"
    "Get-NPSServiceRegistration"

    # SSH & Certificates
    "Get-NPSCertificate"
    "Get-NPSNixCertificate"
    "Get-NPSSSHKeyGenAlgorithm"
    "Get-NPSSshCertificateByDomainUser"
    "Get-NPSSshCertificateByUser"
    "Get-NPSUserSshCertificate"
    "New-NPSUserSshCertificate"

    # Domain Management
    "Get-NPSDomain"

    # Additional Resources
    "Get-NPSSecretVault"
    "Get-NPSWebsite"
    "Get-NPSLog"
    "Get-NPSUser"
    "Get-NPSTotp"

    # Utilities
    "Export-NPSManagedResources"
    "Test-NPSServices"
    "Watch-NPSActionQueue"
    "Get-NPSFavoriteResource"
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


#region ============================================================
# Additional Functions (Ported from SbPAMAPI)
# These functions provide extended functionality for NPS operations
#endregion ==========================================================

function Convert-NPSToken {
    <#
    .SYNOPSIS
        Decodes and parses a JWT token from NPS.

    .DESCRIPTION
        Converts a JWT (JSON Web Token) string into a PowerShell object
        by decoding the Base64Url-encoded payload section.

        This is useful for extracting claims from the token such as:
        - ManagedAccountId
        - User information
        - Token expiration
        - Permissions and roles

    .PARAMETER Token
        The JWT token string to decode. Must be a valid 3-part JWT
        (header.payload.signature).

    .OUTPUTS
        PSCustomObject
        The decoded JWT payload as a PowerShell object with properties
        matching the token claims.

    .EXAMPLE
        $tokenObj = Convert-NPSToken -Token $myToken
        $tokenObj.ManagedAccountId

        Decodes token and extracts the ManagedAccountId claim.

    .EXAMPLE
        $token | Convert-NPSToken | Select-Object exp, iat, ManagedAccountId

        Pipeline usage to extract specific claims.

    .NOTES
        This function only decodes the payload; it does not validate
        the token signature. Use for inspection purposes only.

    .LINK
        Get-NPSToken
        Get-NPSUserToken
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param (
        [Parameter(Mandatory = $true, Position = 0, ValueFromPipeline = $true,
            HelpMessage = "JWT token string to decode")]
        [ValidateNotNullOrEmpty()]
        [System.String] $Token
    )

    process {
        $parts = $token.Split('.')
        if ($parts.length -ne 3) {
            Write-Error "Malformed token: Expected 3 parts, got $($parts.length)"
            return
        }

        # Base64Url decode the payload
        $payload = $parts[1].Replace('-', '+').Replace('_', '/')
        $mod = $parts[1].Length % 4

        switch ($mod) {
            1 { $payload = $payload.Substring(0, $payload.Length - 1) }
            2 { $payload = $payload + "==" }
            3 { $payload = $payload + "=" }
        }

        $json = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($payload))
        return ConvertFrom-Json $json
    }
}

function Get-NPSActivitySessionConfiguration {
    <#
    .SYNOPSIS
        Gets activity session configuration.
    .DESCRIPTION
        Retrieves configuration settings for activity sessions.
    .PARAMETER Id
        Optional session GUID for specific configuration.
    .OUTPUTS
        PSCustomObject
    .EXAMPLE
        Get-NPSActivitySessionConfiguration
    #>
    [CmdletBinding()]
    param (
        [Parameter(Position = 0)]
        [System.Guid] $Id
    )

    $endpoint = "/api/v1/ActivitySession/Config"
    if ($Id) { $endpoint += "/$Id" }
    Invoke-NPSApi -Endpoint $endpoint
}

function Get-NPSActivitySessionCount {
    <#
    .SYNOPSIS
        Gets the count of activity sessions.
    .DESCRIPTION
        Returns the number of activity sessions, optionally filtered by status.
    .PARAMETER Status
        Optional status filter.
    .OUTPUTS
        System.Int32
    .EXAMPLE
        Get-NPSActivitySessionCount -Status "Active"
    #>
    [CmdletBinding()]
    [OutputType([int])]
    param (
        [Parameter(Position = 0)]
        [System.String] $Status
    )

    $endpoint = "/api/v1/ActivitySession/Count"
    if ($Status) { $endpoint += "?status=$Status" }
    Invoke-NPSApi -Endpoint $endpoint
}

function Get-NPSActivitySessionPassword {
    <#
    .SYNOPSIS
        Retrieves the password for an activity session.
    .DESCRIPTION
        Gets the credential password associated with an active
        activity session.
    .PARAMETER Id
        Activity session GUID.
    .OUTPUTS
        System.String
    .EXAMPLE
        Get-NPSActivitySessionPassword -Id "..."
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param (
        [Parameter(Mandatory = $true, Position = 0)]
        [System.Guid] $Id
    )

    Invoke-NPSApi -Endpoint "/api/v1/ActivitySession/$Id/Password"
}

function Get-NPSActivitySessionResource {
    <#
    .SYNOPSIS
        Gets resources available for activity sessions.
    .DESCRIPTION
        Retrieves managed resources that can be used for activity sessions.
    .PARAMETER FilterText
        Text filter for searching resources.
    .PARAMETER DNSHostName
        Filter by DNS hostname.
    .PARAMETER CredentialId
        Filter by credential ID.
    .PARAMETER ResourceId
        Filter by resource ID.
    .EXAMPLE
        Get-NPSActivitySessionResource -FilterText "Windows"
    .LINK
        Start-NPSActivitySession
    #>
    [CmdletBinding()]
    param (
        [Parameter()][string] $FilterText,
        [Parameter()][string] $DNSHostName,
        [Parameter()][Guid] $CredentialId,
        [Parameter()][Guid] $ResourceId
    )
    $resources = @(); $skip = 0; $take = 100
    do {
        $endpoint = "/api/v1/ActivitySession/Resources?skip=$skip&take=$take"
        $body = @{ FilterText = $FilterText }
        $result = Invoke-NPSApi -Endpoint $endpoint -Method POST -Body $body
        $result.Data | ForEach-Object { $resources += $_ }
        $skip += $take
    } until ($resources.Count -ge $result.RecordsTotal)
    
    if ($DNSHostName) { $resources = $resources | Where-Object { $_.DnsHostName -eq $DNSHostName } }
    if ($CredentialId) { $resources = $resources | Where-Object { $_.CredentialId -eq $CredentialId } }
    if ($ResourceId) { $resources = $resources | Where-Object { $_.Id -eq $ResourceId } }
    return $resources
}

function Get-NPSActivitySessionSummary {
    <#
    .SYNOPSIS
        Gets activity session summary information.
    .DESCRIPTION
        Retrieves summary information for activity sessions.
    .PARAMETER Status
        Filter by status: Active, Pending, ApprovalRequired, Historical.
    .PARAMETER Id
        Specific session GUID for summary.
    .OUTPUTS
        PSCustomObject
    .EXAMPLE
        Get-NPSActivitySessionSummary -Status "Active"
    #>
    [CmdletBinding(DefaultParameterSetName = "ByStatus")]
    param (
        [Parameter(Mandatory = $true, ParameterSetName = "ByStatus", Position = 0)]
        [ValidateSet("Active", "Pending", "ApprovalRequired", "Historical")]
        [string] $Status,

        [Parameter(Mandatory = $true, ParameterSetName = "ById", Position = 0)]
        [Guid] $Id
    )

    $endpoint = "/api/v1/ActivitySession/MySummaryByStatus/$Status"
    if ($Id) {
        $endpoint = "/api/v1/ActivitySession/SummaryById/$Id"
    }

    $result = Invoke-NPSApi -Endpoint $endpoint
    if ($Status) { return $result.Data }
    return $result
}

function Get-NPSFavoriteResource {
    <#
    .SYNOPSIS
        Retrieves favorite managed resources for the current user.
    .DESCRIPTION
        Gets resources that the current user has marked as favorites.
    .OUTPUTS
        PSCustomObject[]
    .EXAMPLE
        Get-NPSFavoriteResource
    #>
    [CmdletBinding()]
    param()
    Invoke-NPSApi -Endpoint "/api/v1/ManagedResource/Favorites"
}

function Get-NPSAppUserToken {
    <#
    .SYNOPSIS
        Obtains an application user token using certificate authentication.

    .DESCRIPTION
        Authenticates using a client certificate and credentials to obtain
        an application user token. This method is typically used for
        service accounts and automated processes.

    .PARAMETER Certificate
        X509 certificate for authentication.

    .PARAMETER Credentials
        PSCredential with username and password.

    .PARAMETER Uri
        NPS server URL. Default: "https://localhost:6500"

    .PARAMETER SkipCertificateCheck
        Skip SSL certificate validation.

    .OUTPUTS
        System.String
        JWT access token.

    .EXAMPLE
        $cert = Get-NPSCertificate -CertThumbPrint "ABC123..."
        $cred = Get-Credential
        $token = Get-NPSAppUserToken -Certificate $cert -Credentials $cred -Uri "https://sbpam.company.com"

        Certificate-based authentication.

    .LINK
        Get-NPSUserToken
        Get-NPSCertificate
    #>
    [CmdletBinding()]
    [OutputType([System.String])]
    param (
        [Parameter(Mandatory = $true)]
        [X509Certificate] $Certificate,

        [Parameter(Mandatory = $true)]
        [PSCredential] $Credentials,

        [Parameter(Mandatory = $false)]
        [string] $Uri = "https://localhost:6500",

        [Parameter(Mandatory = $false)]
        [switch] $SkipCertificateCheck
    )

    if (!($Uri -Match "api/v1/AppUserToken")) {
        $Uri = $Uri + "/WebAppApi/api/v1/AppUserToken"
    }

    Write-Verbose "Requesting Application User Token from Uri: $Uri using cert: $($Certificate.SerialNumber)"

    try {
        $userCreds = New-Object System.Net.NetworkCredential($Credentials.UserName, $Credentials.Password)

        $loginBody = @{
            login                   = $userCreds.UserName
            password                = $userCreds.Password
            certificateSerialNumber = $Certificate.SerialNumber
        }
        $body = ConvertTo-Json $loginBody

        $Params = @{
            Certificate = $Certificate
            Body        = $body
            Method      = "Post"
            Uri         = $Uri
        }
        return Invoke-NPSRest @Params -SkipCertificateCheck:$SkipCertificateCheck
    }
    catch {
        Write-Error "Get-NPSAppUserToken Error: $($_) $($_.Exception.InnerException)"
        return $null
    }
}

function Get-NPSAuthenticationMethodTypes {
    <#
    .SYNOPSIS
        Gets available authentication method types.

    .DESCRIPTION
        Retrieves the list of supported authentication methods:
        Password, SshCertificate, SshCertificateAndPassword.

    .PARAMETER Token
        JWT authentication token.

    .PARAMETER Uri
        NPS server URL.

    .PARAMETER SkipCertificateCheck
        Skip SSL certificate validation.

    .OUTPUTS
        System.String[]
        Array of authentication method names.

    .EXAMPLE
        Get-NPSAuthenticationMethodTypes -Token $token

    .LINK
        Get-NPSCredentialTypes
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string] $Token,

        [Parameter(Mandatory = $false)]
        [string] $Uri = "https://localhost:6500",

        [Parameter(Mandatory = $false)]
        [switch] $SkipCertificateCheck
    )

    $Params = @{
        Token = $Token
        Uri   = "$($Uri.TrimEnd("/"))/api/v1/Credential/GetAuthenticationMethodTypes"
    }
    return Invoke-NPSRest @Params -SkipCertificateCheck:$SkipCertificateCheck
}

function Get-NPSCertificate {
    <#
    .SYNOPSIS
        Retrieves a certificate from the Windows certificate store.

    .DESCRIPTION
        Searches the Windows certificate store for a certificate matching
        the specified criteria. Used for certificate-based authentication
        with the NPS API.

    .PARAMETER CertSerialNumber
        Find certificate by serial number.

    .PARAMETER CertThumbPrint
        Find certificate by thumbprint (SHA1 hash).

    .PARAMETER CertFriendlyName
        Find certificate by friendly name.

    .PARAMETER CertSubject
        Find certificate by subject name (supports regex).

    .PARAMETER CertStorePath
        Certificate store path. Default: "Cert:\CurrentUser\My"

    .OUTPUTS
        System.Security.Cryptography.X509Certificates.X509Certificate2
        The matching certificate.

    .EXAMPLE
        Get-NPSCertificate -CertThumbPrint "ABC123DEF456..."

        Finds certificate by thumbprint.

    .EXAMPLE
        $cert = Get-NPSCertificate -CertSubject "CN=NPSApp"
        Get-NPSAppUserToken -Certificate $cert -Credentials $cred

        Gets certificate and uses it for app authentication.

    .LINK
        Get-NPSNixCertificate
        Get-NPSAppUserToken
    #>
    [CmdletBinding()]
    param (
        [Parameter(ParameterSetName = "SerialNumber", Mandatory)]
        [string] $CertSerialNumber,

        [Parameter(ParameterSetName = "Thumbprint", Mandatory)]
        [string] $CertThumbPrint,

        [Parameter(ParameterSetName = "FriendlyName", Mandatory)]
        [string] $CertFriendlyName,

        [Parameter(ParameterSetName = "Subject", Mandatory)]
        [string] $CertSubject,

        [Parameter(Mandatory = $false)]
        [string] $CertStorePath = "Cert:\CurrentUser\My"
    )

    if (![string]::IsNullOrEmpty($CertSerialNumber)) {
        $CertSerialNumber = $CertSerialNumber.Replace(" ", "").Trim()
        $certificate = Get-ChildItem -Path $CertStorePath | Where-Object { $_.SerialNumber -match $CertSerialNumber }
        Write-Verbose "Using Certificate Serial Number: $($certificate.SerialNumber)"
    }
    elseif (![string]::IsNullOrEmpty($CertThumbPrint)) {
        $certificate = Get-ChildItem -Path $CertStorePath | Where-Object { $_.ThumbPrint -match $CertThumbPrint }
        Write-Verbose "Using Certificate ThumbPrint: $($certificate.Thumbprint)"
    }
    elseif (![string]::IsNullOrEmpty($CertFriendlyName)) {
        $certificate = Get-ChildItem -Path $CertStorePath | Where-Object { $_.FriendlyName -match $CertFriendlyName }
        Write-Verbose "Using Certificate Friendly Name: $($certificate.FriendlyName)"
    }
    elseif (![string]::IsNullOrEmpty($CertSubject)) {
        $certificate = Get-ChildItem -Path $CertStorePath | Where-Object { $_.Subject -match $CertSubject }
        Write-Verbose "Using Certificate Subject: $($certificate.Subject)"
    }
    else {
        $certificate = $null
    }

    if ($null -eq $certificate) {
        Write-Error "No Certificate found"
        throw "No Certificate found"
    }

    return $certificate
}

function Get-NPSCiscoEnablePassword {
    <#
    .SYNOPSIS
        Gets the Cisco enable password for a session.
    .DESCRIPTION
        Retrieves the enable mode password for Cisco device access.
    .PARAMETER SessionId
        Activity session GUID.
    .EXAMPLE
        Get-NPSCiscoEnablePassword -SessionId $sessionId
    .LINK
        Start-NPSActivitySession
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, Position = 0)][Guid] $SessionId
    )
    Invoke-NPSApi -Endpoint "/api/v1/ActivitySession/$SessionId/CiscoEnablePassword"
}

function Get-NPSCiscoEnablePasswordByCredential {
    <#
    .SYNOPSIS
        Gets Cisco enable password by credential ID.
    .DESCRIPTION
        Retrieves the enable password associated with a credential.
    .PARAMETER CredentialId
        Credential GUID.
    .EXAMPLE
        Get-NPSCiscoEnablePasswordByCredential -CredentialId $credId
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, Position = 0)][Guid] $CredentialId
    )
    Invoke-NPSApi -Endpoint "/api/v1/Credential/$CredentialId/CiscoEnablePassword"
}

function Get-NPSCredentialSshCertificate {
    <#
    .SYNOPSIS
        Gets an SSH certificate by credential ID.
    .PARAMETER CredentialId
        Credential GUID.
    .EXAMPLE
        Get-NPSCredentialSshCertificate -CredentialId $credId
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, Position = 0)][Guid] $CredentialId
    )
    Invoke-NPSApi -Endpoint "/api/v1/Credential/GetCredentialSshCertificate/$CredentialId"
}

function Get-NPSCredentialTypes {
    <#
    .SYNOPSIS
        Gets available credential types.
    .DESCRIPTION
        Retrieves the list of supported credential types in NPS.
    .OUTPUTS
        System.String[]
    .EXAMPLE
        Get-NPSCredentialTypes
    #>
    [CmdletBinding()]
    param()
    Invoke-NPSApi -Endpoint "/api/v1/Credential/GetCredentialTypes"
}

function Get-NPSDomain {
    <#
    .SYNOPSIS
        Gets Active Directory domain information.
    .DESCRIPTION
        Retrieves domain configuration.
    .PARAMETER Id
        Domain GUID.
    .PARAMETER DomainConfigurationId
        Domain configuration GUID.
    .EXAMPLE
        Get-NPSDomain -Id $domainId
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, ParameterSetName = "ById", Position = 0)][Guid] $Id,
        [Parameter(Mandatory = $true, ParameterSetName = "ByDomainConfigurationId")][Guid] $DomainConfigurationId
    )
    if ($DomainConfigurationId) {
        $endpoint = "/api/v1/ActiveDirectory/Domain/ByDomainConfiguration/$DomainConfigurationId"
    }
    else {
        $endpoint = "/api/v1/ActiveDirectory/Domain/$Id"
    }
    Invoke-NPSApi -Endpoint $endpoint
}

function Get-NPSManagedResourceSshFingerprint {
    <#
    .SYNOPSIS
        Gets the SSH fingerprint for a managed resource.
    .PARAMETER ResourceId
        Managed resource GUID.
    .EXAMPLE
        Get-NPSManagedResourceSshFingerprint -ResourceId $resourceId
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, Position = 0)][System.Guid] $ResourceId
    )
    Invoke-NPSApi -Endpoint "/api/v1/ManagedResource/GetSshFingerprint/$ResourceId"
}

function Get-NPSMfaToken {
    <#
    .SYNOPSIS
        Completes MFA verification.
    .PARAMETER Token
        Pre-MFA token.
    .PARAMETER Code
        6-digit TOTP code.
    .EXAMPLE
        Get-NPSMfaToken -Token $preToken -Code "123456"
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string] $Token,
        [Parameter(Mandatory = $true)][string] $Code
    )
    $params = @{
        Uri         = "$($Script:NPSSession.Server)/signin2fa"
        Method      = "POST"
        Body        = "`"$Code`""
        Headers     = @{ Authorization = "Bearer $Token" }
        ContentType = "application/json"
    }
    Invoke-RestMethod @params
}

function Get-NPSNixCertificate {
    <#
    .SYNOPSIS
        Retrieves a certificate from the certificate store on Linux/macOS.

    .DESCRIPTION
        Searches the X509 certificate store for a certificate matching
        the specified criteria. Used for certificate-based authentication
        on non-Windows platforms.

    .PARAMETER CertSerialNumber
        Find certificate by serial number.

    .PARAMETER CertThumbPrint
        Find certificate by thumbprint (SHA1 hash).

    .PARAMETER CertFriendlyName
        Find certificate by friendly name.

    .PARAMETER CertSubject
        Find certificate by subject name (supports regex).

    .PARAMETER CertStore
        Certificate store name. Default: "My"

    .OUTPUTS
        System.Security.Cryptography.X509Certificates.X509Certificate2
        The matching certificate, or $null if not found.

    .EXAMPLE
        Get-NPSNixCertificate -CertThumbPrint "ABC123..."

        Finds certificate by thumbprint.

    .EXAMPLE
        Get-NPSNixCertificate -CertSubject "CN=NPS*" -CertStore "My"

        Finds certificate by subject pattern.

    .LINK
        Get-NPSCertificate
        Get-NPSAppUserToken
    #>
    [CmdletBinding()]
    param (
        [Parameter(ParameterSetName = "SerialNumber", Mandatory)]
        [string] $CertSerialNumber,

        [Parameter(ParameterSetName = "Thumbprint", Mandatory)]
        [string] $CertThumbPrint,

        [Parameter(ParameterSetName = "Friendlyname", Mandatory)]
        [string] $CertFriendlyName,

        [Parameter(ParameterSetName = "Subject", Mandatory)]
        [string] $CertSubject,

        [Parameter(Mandatory = $false)]
        [string] $CertStore = "My"
    )

    $store = New-Object System.Security.Cryptography.X509Certificates.X509Store($CertStore)
    $store.Open("ReadOnly")
    $certificate = $null

    Write-Verbose "Using certificate store: $CertStore"

    if (![string]::IsNullOrEmpty($CertSerialNumber)) {
        $CertSerialNumber = $CertSerialNumber.Replace(" ", "").Trim()
        foreach ($certificate in $store.Certificates) {
            if ($certificate.SerialNumber -match $CertSerialNumber) {
                Write-Verbose "Using Certificate Serial Number: $($certificate.SerialNumber)"
                break
            }
        }
    }
    elseif (![string]::IsNullOrEmpty($CertThumbPrint)) {
        foreach ($certificate in $store.Certificates) {
            if ($certificate.ThumbPrint -match $CertThumbPrint) {
                Write-Verbose "Using Certificate Thumbprint: $($certificate.ThumbPrint)"
                break
            }
        }
    }
    elseif (![string]::IsNullOrEmpty($CertFriendlyName)) {
        foreach ($certificate in $store.Certificates) {
            if ($certificate.FriendlyName -match $CertFriendlyName) {
                Write-Verbose "Using Certificate FriendlyName: $($certificate.FriendlyName)"
                break
            }
        }
    }
    elseif (![string]::IsNullOrEmpty($CertSubject)) {
        foreach ($certificate in $store.Certificates) {
            if ($certificate.Subject -match $CertSubject) {
                Write-Verbose "Using Certificate Subject: $($certificate.Subject)"
                break
            }
        }
    }
    else {
        $certificate = $null
    }
    return $certificate
}

function Get-NPSSSHKeyGenAlgorithm {
    <#
    .SYNOPSIS
        Gets available SSH key generation algorithms.
    .DESCRIPTION
        Retrieves supported SSH key algorithms (RSA, ECDSA, Ed25519).
    .PARAMETER Token
        JWT authentication token.
    .EXAMPLE
        Get-NPSSSHKeyGenAlgorithm -Token $token
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string] $Token,
        [Parameter(Mandatory = $false)][string] $Uri = "https://localhost:6500",
        [Parameter(Mandatory = $false)][switch] $SkipCertificateCheck
    )
    $Params = @{ Token = $Token; Uri = "$($Uri.TrimEnd("/"))/api/v1/Credential/SSHKeyGenAlgorithms" }
    return Invoke-NPSRest @Params -SkipCertificateCheck:$SkipCertificateCheck
}

function Get-NPSSettings {
    <#
    .SYNOPSIS
        Gets NPS system settings.

    .DESCRIPTION
        Retrieves system configuration settings.

        WARNING: The /api/v1/Settings endpoint does not exist in NPS v25.12.
        This function is kept for forward compatibility but will return 404.

    .OUTPUTS
        PSCustomObject
        Settings object (if endpoint becomes available).

    .EXAMPLE
        Get-NPSSettings

        Attempts to get system settings.

    .NOTES
        This endpoint returns 404 in NPS v25.12.00000.
        The endpoint may be available in future versions.

    .LINK
        Get-NPSHealth
        Get-NPSVersion
    #>
    [CmdletBinding()]
    param()

    Write-Warning "The /api/v1/Settings endpoint may not exist in your NPS version."
    Invoke-NPSApi -Endpoint "/api/v1/Settings"
}

function Get-NPSSshCertificateByDomainUser {
    <#
    .SYNOPSIS
        Gets SSH certificate by domain and username.
    .PARAMETER DomainName
        Domain name.
    .PARAMETER UserName
        Username.
    .EXAMPLE
        Get-NPSSshCertificateByDomainUser -DomainName "CORP" -UserName "jsmith"
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string] $DomainName,
        [Parameter(Mandatory = $true)][string] $UserName
    )
    Invoke-NPSApi -Endpoint "/api/v1/Credential/GetSshCertificateByDomainUser/$DomainName/$UserName"
}

function Get-NPSSshCertificateByUser {
    <#
    .SYNOPSIS
        Gets SSH certificate by username.
    .PARAMETER UserName
        Username.
    .EXAMPLE
        Get-NPSSshCertificateByUser -UserName "jsmith"
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, Position = 0)][string] $UserName
    )
    Invoke-NPSApi -Endpoint "/api/v1/Credential/GetSshCertificateByUser/$UserName"
}

function Get-NPSToken {
    <#
    .SYNOPSIS
        Obtains a pre-MFA token using username and password.
    .DESCRIPTION
        First step of authentication.
    .PARAMETER Username
        Username for authentication.
    .PARAMETER Password
        Password for authentication.
    .OUTPUTS
        System.String
    .EXAMPLE
        Get-NPSToken -Username "admin" -Password "pass"
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true, Position = 0)][string] $Username,
        [Parameter(Mandatory = $true, Position = 1)][string] $Password
    )

    $body = @{ login = $Username; password = $Password } | ConvertTo-Json
    $params = @{
        Uri         = "$($Script:NPSSession.Server)/signinBody"
        Method      = "POST"
        Body        = $body
        ContentType = "application/json"
    }
    Invoke-RestMethod @params
}

function Get-NPSTotp {
    <#
    .SYNOPSIS
        Generates a Time-based One-Time Password (TOTP) for MFA authentication.

    .DESCRIPTION
        Calculates a 6-digit TOTP code from a Base32-encoded secret key.
        This is used for completing MFA authentication when obtaining
        a full access token from the NPS server.

        The TOTP algorithm follows RFC 6238 using HMAC-SHA1 with a
        configurable time window (default 30 seconds).

    .PARAMETER Secret
        The Base32-encoded secret key from your authenticator app setup.
        This is the secret provided when configuring MFA for your account.

    .PARAMETER TimeWindow
        The time step in seconds for TOTP calculation.
        Default: 30 seconds (standard TOTP interval)

    .OUTPUTS
        System.String
        A 6-digit TOTP code padded with leading zeros if necessary.

    .EXAMPLE
        Get-NPSTotp -Secret "JBSWY3DPEHPK3PXP"

        Generates a TOTP code using the provided secret.

    .EXAMPLE
        $code = Get-NPSTotp -Secret $env:SBPAM_MFA_SECRET
        Get-NPSMfaToken -Token $preToken -Code $code

        Uses environment variable for secret and passes to MFA token request.

    .NOTES
        The secret should be stored securely and not hardcoded in scripts.
        Consider using environment variables or secure vaults.

    .LINK
        Get-NPSUserToken
        Get-NPSMfaToken
    #>
    [CmdletBinding()]
    [OutputType([System.String])]
    param (
        [Parameter(Mandatory = $true, Position = 0,
            HelpMessage = "Base32-encoded secret key from authenticator setup")]
        [ValidateNotNullOrEmpty()]
        [System.String] $Secret,

        [Parameter(Mandatory = $false,
            HelpMessage = "Time step in seconds (default 30)")]
        [ValidateRange(1, 120)]
        [System.Int64] $TimeWindow = 30
    )

    # Base32 character set for decoding
    $Script:Base32Charset = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'

    # Convert the secret from Base32 to byte array
    $bigInteger = [Numerics.BigInteger]::Zero
    foreach ($char in ($secret.ToUpper() -replace '[^A-Z2-7]').GetEnumerator()) {
        $bigInteger = ($bigInteger -shl 5) -bor ($Script:Base32Charset.IndexOf($char))
    }
    [byte[]]$secretAsBytes = $bigInteger.ToByteArray()

    # Handle big endian 2's complement
    if ($secretAsBytes[-1] -eq 0) {
        $secretAsBytes = $secretAsBytes[0..($secretAsBytes.Count - 2)]
    }

    # Convert little endian to big endian
    [array]::Reverse($secretAsBytes)

    # Calculate time counter
    $epochTime = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
    $timeBytes = [BitConverter]::GetBytes([int64][math]::Floor($epochTime / $TimeWindow))
    if ([BitConverter]::IsLittleEndian) {
        [array]::Reverse($timeBytes)
    }

    # Calculate HMAC-SHA1
    $hmacGen = [Security.Cryptography.HMACSHA1]::new($secretAsBytes)
    $hash = $hmacGen.ComputeHash($timeBytes)

    # Dynamic truncation
    $offset = $hash[$hash.Length - 1] -band 0xF
    $fourBytes = $hash[$offset..($offset + 3)]
    if ([BitConverter]::IsLittleEndian) {
        [array]::Reverse($fourBytes)
    }

    # Generate 6-digit code
    $num = [BitConverter]::ToInt32($fourBytes, 0) -band 0x7FFFFFFF
    return ($num % 1000000).ToString().PadLeft(6, '0')
}

function Get-NPSUserPolicy {
    <#
    .SYNOPSIS
        Retrieves access control policies for the current user.
    .DESCRIPTION
        Gets the access control policies associated with the current user.
    .OUTPUTS
        PSCustomObject[]
    .EXAMPLE
        Get-NPSUserPolicy
    #>
    [CmdletBinding()]
    param ()

    $tokenObj = Convert-NPSToken -Token $Script:NPSSession.Token
    Invoke-NPSApi -Endpoint "/api/v1/AccessControlPolicy/ManagedAccount/$($tokenObj.managedAccountId)"
}

function Get-NPSUserSshCertificate {
    <#
    .SYNOPSIS
        Gets SSH certificates for a user.
    .PARAMETER UserId
        User GUID.
    .EXAMPLE
        Get-NPSUserSshCertificate -UserId $userId
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, Position = 0)][Guid] $UserId
    )
    Invoke-NPSApi -Endpoint "/api/v1/Credential/GetUserSshCertificate/$UserId"
}

function Get-NPSUserToken {
    <#
    .SYNOPSIS
        Obtains a full access token using username/password and MFA.

    .DESCRIPTION
        Performs the complete two-step authentication flow:
        1. Authenticates with username/password to get a pre-MFA token
        2. Generates TOTP code from the user's MFA secret
        3. Completes MFA verification to get a full access token

        This is the primary authentication method for interactive scripts.

    .PARAMETER Credentials
        PSCredential object containing username and password.
        Use Get-Credential to create interactively.

    .PARAMETER UserSecret
        Base32-encoded MFA secret for TOTP generation.
        This is the secret from your authenticator app setup.

    .PARAMETER Uri
        NPS server URL. Default: "https://localhost:6500"

    .PARAMETER SkipCertificateCheck
        Skip SSL certificate validation.

    .OUTPUTS
        System.String
        JWT access token for API authentication.

    .EXAMPLE
        $cred = Get-Credential
        $token = Get-NPSUserToken -Credentials $cred -UserSecret "JBSWY3DPEHPK3PXP" -Uri "https://sbpam.company.com"

        Interactive credential prompt with MFA.

    .EXAMPLE
        $secPwd = ConvertTo-SecureString "P@ssw0rd" -AsPlainText -Force
        $cred = New-Object PSCredential("admin", $secPwd)
        $token = Get-NPSUserToken -Credentials $cred -UserSecret $env:MFA_SECRET -Uri $env:SBPAM_URL

        Automated authentication using environment variables.

    .NOTES
        Tokens expire after approximately 15 minutes.
        Store the MFA secret securely - never hardcode in scripts.

    .LINK
        Get-NPSAppUserToken
        Get-NPSToken
        Get-NPSMfaToken
    #>
    [CmdletBinding()]
    [OutputType([System.String])]
    param (
        [Parameter(Mandatory = $true,
            HelpMessage = "PSCredential with username and password")]
        [PSCredential] $Credentials,

        [Parameter(Mandatory = $true,
            HelpMessage = "Base32 MFA secret for TOTP")]
        [string] $UserSecret,

        [Parameter(Mandatory = $false,
            HelpMessage = "NPS server URL")]
        [string] $Uri = "https://localhost:6500",

        [Parameter(Mandatory = $false)]
        [switch] $SkipCertificateCheck
    )

    # Create web session
    $WebSession = New-Object Microsoft.PowerShell.Commands.WebRequestSession
    $userCreds = $Credentials.GetNetworkCredential()

    # Get pre-MFA token
    $Params = @{
        Credentials = $userCreds
        WebSession  = $WebSession
        Uri         = $Uri
    }
    $token = Get-NPSToken @Params -SkipCertificateCheck:$SkipCertificateCheck -ErrorAction Stop

    # Generate TOTP code
    $userCode = Get-NPSTotp -Secret $UserSecret

    # Complete MFA
    $Params = @{
        Token      = $token
        Code       = $userCode
        WebSession = $WebSession
        Uri        = $Uri
    }
    return Get-NPSMfaToken @Params -SkipCertificateCheck:$SkipCertificateCheck
}

function New-NPSUserSshCertificate {
    <#
    .SYNOPSIS
        Generates a new SSH certificate for a user.
    .DESCRIPTION
        Creates a new SSH certificate credential with specified algorithm.
    .PARAMETER UserId
        User GUID to generate certificate for.
    .PARAMETER KeyGenAlgorithm
        Algorithm: RSA, ECDSA, Ed25519. Default: RSA
    .PARAMETER KeyLength
        Key length in bits (for RSA).
    .PARAMETER AutoGenPassphrase
        Auto-generate passphrase. Default: true
    .EXAMPLE
        New-NPSUserSshCertificate -UserId $userId -KeyGenAlgorithm "RSA" -KeyLength 4096
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, Position = 0)][Guid] $UserId,
        [Parameter()][bool] $AutoGenPassphrase = $true,
        [Parameter()][object] $Passphrase,
        [Parameter()][ValidateSet("RSA", "ECDSA", "Ed25519")][string] $KeyGenAlgorithm = "RSA",
        [Parameter()][int] $KeyLength,
        [Parameter()][ValidateSet("Any", "Configuration", "User", "Service", "ActivityToken", "Application", "VaultUser", "SshKeyCert")][string] $CredentialType = "SshKeyCert",
        [Parameter()][ValidateSet("Password", "SshCertificate", "SshCertificateAndPassword")][string] $AuthenticationMethod
    )

    if ($Passphrase -is [System.Security.SecureString]) {
        $Passphrase = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($Passphrase))
    }

    $sshBody = @{ 
        autoGenPassphrase    = $AutoGenPassphrase
        passphrase           = $Passphrase
        keyGenAlgorithm      = $KeyGenAlgorithm
        keyLength            = $KeyLength
        credentialType       = $CredentialType
        authenticationMethod = $AuthenticationMethod 
    }
    
    Invoke-NPSApi -Endpoint "/api/v1/Credential/GenerateUserSshCertificate/$UserId" -Method POST -Body $sshBody
}

function Search-NPSActiveSession {
    <#
    .SYNOPSIS
        Searches active sessions for specific content.
    .DESCRIPTION
        Searches currently active sessions for matching content (StdIn, StdOut, etc).
    .PARAMETER SearchFilter
        Text to search for in session content.
    .PARAMETER Key
        Content type: All, Windows_Audit, StdIn, StdOut. Default: All
    .EXAMPLE
        Search-NPSActiveSession -SearchFilter "password"
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, Position = 0)][string] $SearchFilter,
        [Parameter()][ValidateSet("All", "Windows_Audit", "StdIn", "StdOut")][string] $Key = "All"
    )
    $body = @{ searchFilter = $SearchFilter; key = $Key }
    Invoke-NPSApi -Endpoint "/api/v1/ReplaySession/SearchActiveSessions" -Method POST -Body $body
}

function Search-NPSHistoricalSession {
    <#
    .SYNOPSIS
        Searches historical sessions for specific content.
    .DESCRIPTION
        Searches completed session recordings for matching content.
    .PARAMETER SearchFilter
        Text to search for.
    .PARAMETER Key
        Content type: All, Windows_Audit, StdIn, StdOut. Default: All
    .EXAMPLE
        Search-NPSHistoricalSession -SearchFilter "rm -rf"
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, Position = 0)][string] $SearchFilter,
        [Parameter()][ValidateSet("All", "Windows_Audit", "StdIn", "StdOut")][string] $Key = "All"
    )
    $body = @{ searchFilter = $SearchFilter; key = $Key }
    Invoke-NPSApi -Endpoint "/api/v1/ReplaySession/SearchHistoricalSessions" -Method POST -Body $body
}

function Set-NPSManagedResourceTrustThumbprint {
    <#
    .SYNOPSIS
        Sets the trusted SSH thumbprint for a managed resource.
    .PARAMETER ResourceId
        Managed resource GUID.
    .EXAMPLE
        Set-NPSManagedResourceTrustThumbprint -ResourceId $resourceId
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, Position = 0)][System.Guid] $ResourceId
    )
    Invoke-NPSApi -Endpoint "/api/v1/ManagedResource/$ResourceId/Trust" -Method PUT
}

function Start-NPSActivitySession {
    <#
    .SYNOPSIS
        Starts a new activity session for privileged access.
    .DESCRIPTION
        Creates and starts a new activity session.
    .PARAMETER ActivityName
        Name of the activity type (e.g., "RDP", "SSH").
    .PARAMETER ResourceId
        Managed resource GUID.
    .PARAMETER ResourceName
        Managed resource name.
    .PARAMETER CredentialId
        Credential GUID.
    .PARAMETER CredentialName
        Credential name.
    .EXAMPLE
        Start-NPSActivitySession -ActivityName "RDP" -ResourceName "Server01" -CredentialName "Admin"
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string] $ActivityName,

        [Parameter(Mandatory = $false, ParameterSetName = "ResourceId")]
        [Guid] $ResourceId,

        [Parameter(Mandatory = $false, ParameterSetName = "ResourceName")]
        [string] $ResourceName,

        [Parameter(Mandatory = $false, ParameterSetName = "CredentialId")]
        [Guid] $CredentialId,

        [Parameter(Mandatory = $false, ParameterSetName = "CredentialName")]
        [string] $CredentialName,

        [Parameter(Mandatory = $false)]
        [DateTime] $StartTime,

        [Parameter(Mandatory = $false)]
        [DateTime] $EndTime
    )

    $StartTimeUtc = if ($StartTime) { $StartTime.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ") } else { (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ") }
    $EndTimeUtc = if ($EndTime) { $EndTime.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ") } else { $null }

    $tokenObj = Convert-NPSToken -Token $Script:NPSSession.Token
    $request = @{
        activityName     = $ActivityName
        managedAccountId = $tokenObj.managedAccountId
        startDateTimeUtc = $StartTimeUtc
        endDateTimeUtc   = $EndTimeUtc
    }

    if ($CredentialId) { $request.credentialId = $CredentialId }
    if ($ResourceId) { $request.managedResourceId = $ResourceId }
    if ($ResourceName) { $request.managedResourceName = $ResourceName }
    if ($CredentialName) { $request.credentialName = $CredentialName }

    Invoke-NPSApi -Endpoint "/api/v1/ActivitySession" -Method POST -Body $request
}

function Stop-NPSActivitySession {
    <#
    .SYNOPSIS
        Stops an active activity session.

    .DESCRIPTION
        Terminates an activity session and releases the associated
        credential. The session must be in an active state.

    .PARAMETER Id
        Activity session GUID to stop.

    .OUTPUTS
        PSCustomObject
        Result of the stop operation.

    .EXAMPLE
        Stop-NPSActivitySession -Id "12345678-1234-1234-1234-123456789abc"

        Stops the specified session.

    .EXAMPLE
        Get-NPSActivitySession -Active | ForEach-Object {
            Stop-NPSActivitySession -Id $_.id
        }

        Stops all active sessions.

    .LINK
        Start-NPSActivitySession
        Get-NPSActivitySession
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true, Position = 0)]
        [System.Guid] $Id
    )

    Invoke-NPSApi -Endpoint "/api/v1/ActivitySession/$Id" -Method DELETE
}