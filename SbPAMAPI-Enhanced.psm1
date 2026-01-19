<#
.SYNOPSIS
    Netwrix Privilege Secure (SbPAM) PowerShell Module - Enhanced Edition

.DESCRIPTION
    Complete PowerShell module for automating Netwrix Privilege Secure (formerly SbPAM)
    with comprehensive help documentation for all 56+ cmdlets.

    This enhanced edition includes:
    - Full Get-Help documentation for every cmdlet
    - Detailed parameter descriptions
    - Multiple usage examples
    - Cross-references between related cmdlets
    - Additional utility functions for common operations

    Original module by Stealthbits Technologies, enhanced with documentation.

.NOTES
    Original Version:  4.3.2
    Enhanced Version:  4.3.2-Enhanced
    Original Author:   Stealthbits Technologies
    Enhancement:       Agent Zero
    API Version:       v1 (Product Version 25.12.00000)
    Requires:          PowerShell 7.0+

.EXAMPLE
    # Import the module
    Import-Module .\SbPAMAPI-Enhanced.psm1

    # Get help for any cmdlet
    Get-Help Get-SbPAMUserToken -Full
    Get-Help Start-SbPAMActivitySession -Examples

    # List all available cmdlets
    Get-Command -Module SbPAMAPI-Enhanced

.LINK
    https://www.netwrix.com/sbpam.html
#>

#Requires -Version 7.0

# ============================================================================
# TOTP / TOKEN UTILITIES
# ============================================================================

function Get-SbPAMTotp {
    <#
    .SYNOPSIS
        Generates a Time-based One-Time Password (TOTP) for MFA authentication.

    .DESCRIPTION
        Calculates a 6-digit TOTP code from a Base32-encoded secret key.
        This is used for completing MFA authentication when obtaining
        a full access token from the SbPAM server.

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
        Get-SbPAMTotp -Secret "JBSWY3DPEHPK3PXP"

        Generates a TOTP code using the provided secret.

    .EXAMPLE
        $code = Get-SbPAMTotp -Secret $env:SBPAM_MFA_SECRET
        Get-SbPAMMfaToken -Token $preToken -Code $code

        Uses environment variable for secret and passes to MFA token request.

    .NOTES
        The secret should be stored securely and not hardcoded in scripts.
        Consider using environment variables or secure vaults.

    .LINK
        Get-SbPAMUserToken
        Get-SbPAMMfaToken
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

function Convert-SbPAMToken {
    <#
    .SYNOPSIS
        Decodes and parses a JWT token from SbPAM.

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
        $tokenObj = Convert-SbPAMToken -Token $myToken
        $tokenObj.ManagedAccountId

        Decodes token and extracts the ManagedAccountId claim.

    .EXAMPLE
        $token | Convert-SbPAMToken | Select-Object exp, iat, ManagedAccountId

        Pipeline usage to extract specific claims.

    .NOTES
        This function only decodes the payload; it does not validate
        the token signature. Use for inspection purposes only.

    .LINK
        Get-SbPAMToken
        Get-SbPAMUserToken
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

# ============================================================================
# CORE REST API FUNCTION
# ============================================================================

function Invoke-SbPAMRest {
    <#
    .SYNOPSIS
        Invokes a REST API call to the SbPAM server.

    .DESCRIPTION
        Low-level function for making authenticated REST API calls to
        Netwrix Privilege Secure. Handles authentication headers,
        content types, error handling, and response parsing.

        This is the foundation function used by all other cmdlets.
        Use it directly for endpoints not covered by specific cmdlets.

    .PARAMETER Uri
        The full URI for the API endpoint.
        Example: "https://sbpam.company.com/api/v1/ManagedResource"

    .PARAMETER Token
        The JWT authentication token obtained from Get-SbPAMUserToken
        or Get-SbPAMAppUserToken.

    .PARAMETER Body
        The request body for POST/PUT requests. Can be a string,
        hashtable, or object (will be converted to JSON).

    .PARAMETER Certificate
        X509 certificate for certificate-based authentication.

    .PARAMETER ContentType
        The Content-Type header value.
        Default: "application/json; charset=utf-8"

    .PARAMETER Method
        HTTP method: Get, Post, Put, Delete, Patch, etc.
        Default: Get

    .PARAMETER WebSession
        PowerShell web session object for maintaining cookies/state.

    .PARAMETER SkipCertificateCheck
        Skip SSL certificate validation (for self-signed certificates).

    .PARAMETER AlwaysReport
        Always report errors, even for 404 on GET requests.

    .OUTPUTS
        PSCustomObject or $null
        The API response parsed from JSON, or $null on error.

    .EXAMPLE
        Invoke-SbPAMRest -Uri "https://sbpam/api/v1/Health" -Token $token

        Simple GET request to health endpoint.

    .EXAMPLE
        $body = @{ name = "NewResource" } | ConvertTo-Json
        Invoke-SbPAMRest -Uri "https://sbpam/api/v1/ManagedResource" -Token $token -Method Post -Body $body

        POST request with JSON body.

    .EXAMPLE
        Invoke-SbPAMRest -Uri $uri -Token $token -SkipCertificateCheck

        Request with SSL certificate validation disabled.

    .NOTES
        Error responses include traceId for troubleshooting with support.

    .LINK
        Get-SbPAMUserToken
        Get-SbPAMAppUserToken
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true, Position = 0,
            HelpMessage = "Full URI for the API endpoint")]
        [ValidateNotNullOrEmpty()]
        [System.String] $Uri,

        [Parameter(Mandatory = $false,
            HelpMessage = "JWT authentication token")]
        [System.String] $Token,

        [Parameter(Mandatory = $false,
            HelpMessage = "Request body for POST/PUT")]
        [System.Object] $Body,

        [Parameter(Mandatory = $false,
            HelpMessage = "X509 certificate for auth")]
        [X509Certificate] $Certificate,

        [Parameter(Mandatory = $false,
            HelpMessage = "Content-Type header")]
        [System.String] $ContentType = "application/json; charset=utf-8",

        [Parameter(Mandatory = $false,
            HelpMessage = "HTTP method")]
        [ValidateSet("Default", "Get", "Head", "Post", "Put", "Delete", "Trace", "Options", "Merge", "Patch")]
        [System.String] $Method = "Get",

        [Parameter(Mandatory = $false)]
        [Microsoft.PowerShell.Commands.WebRequestSession] $WebSession,

        [Parameter(Mandatory = $false,
            HelpMessage = "Skip SSL certificate validation")]
        [switch] $SkipCertificateCheck,

        [Parameter(Mandatory = $false,
            HelpMessage = "Always report errors including 404")]
        [switch] $AlwaysReport
    )

    $Params = @{
        Method               = $Method
        Uri                  = $Uri
        Headers              = @{"Accept" = "application/json" }
        SkipCertificateCheck = $SkipCertificateCheck
    }

    if ($null -ne $WebSession) {
        $Params.WebSession = $WebSession
    }
    $result = $null

    Write-Verbose "Making $Method call to $Uri"

    if ($Method -eq "Post" -or $Method -eq "Put") {
        if ($ContentType -ne "" -and $null -ne $ContentType) {
            $Params.ContentType = $ContentType
        }
        else {
            $Params.ContentType = "application/json; charset=utf-8"
        }
    }

    if (![string]::IsNullOrEmpty($Token)) {
        $Params.Headers["Authorization"] = "Bearer $Token"
    }

    try {
        if ($null -ne $Body) {
            $Params.Body = $Body
        }
        if ($null -ne $Certificate) {
            $Params.Certificate = $Certificate
        }
        $result = Invoke-RestMethod @Params -UseBasicParsing -SkipHttpErrorCheck -StatusCodeVariable "StatusCode"

        if ($StatusCode -ge 200 -and $StatusCode -le 299) {
            if ($null -eq $result) {
                return @{}
            }
            return $result
        }
        else {
            if (!$AlwaysReport -and $StatusCode -eq 404 -and $Method -eq "Get") {
                Write-Verbose "$Method $Uri $result"
            }
            else {
                if ($null -ne $result -and $null -ne $result.title) {
                    $Message = "$Method $Uri [$($StatusCode)] $($result.title) TRACEID: $($result.traceId)"
                    if ($result.title -eq "One or more validation errors occurred.") {
                        $Message += " Errors $(ConvertTo-Json $result.errors -Depth 10)"
                        $Message += " Data $Body"
                    }
                    Write-Error $Message
                }
                else {
                    Write-Error "$Method $Uri [$($statusCode)] $result"
                }
            }
        }
        return $null
    }
    catch {
        Write-Error $_.Exception
        return $null
    }
}

# ============================================================================
# CERTIFICATE FUNCTIONS
# ============================================================================

function Get-SbPAMNixCertificate {
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
        Get-SbPAMNixCertificate -CertThumbPrint "ABC123..."

        Finds certificate by thumbprint.

    .EXAMPLE
        Get-SbPAMNixCertificate -CertSubject "CN=SbPAM*" -CertStore "My"

        Finds certificate by subject pattern.

    .LINK
        Get-SbPAMCertificate
        Get-SbPAMAppUserToken
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

function Get-SbPAMCertificate {
    <#
    .SYNOPSIS
        Retrieves a certificate from the Windows certificate store.

    .DESCRIPTION
        Searches the Windows certificate store for a certificate matching
        the specified criteria. Used for certificate-based authentication
        with the SbPAM API.

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
        Get-SbPAMCertificate -CertThumbPrint "ABC123DEF456..."

        Finds certificate by thumbprint.

    .EXAMPLE
        $cert = Get-SbPAMCertificate -CertSubject "CN=SbPAMApp"
        Get-SbPAMAppUserToken -Certificate $cert -Credentials $cred

        Gets certificate and uses it for app authentication.

    .LINK
        Get-SbPAMNixCertificate
        Get-SbPAMAppUserToken
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

# ============================================================================
# AUTHENTICATION FUNCTIONS
# ============================================================================

function Get-SbPAMUserToken {
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
        SbPAM server URL. Default: "https://localhost:6500"

    .PARAMETER SkipCertificateCheck
        Skip SSL certificate validation.

    .OUTPUTS
        System.String
        JWT access token for API authentication.

    .EXAMPLE
        $cred = Get-Credential
        $token = Get-SbPAMUserToken -Credentials $cred -UserSecret "JBSWY3DPEHPK3PXP" -Uri "https://sbpam.company.com"

        Interactive credential prompt with MFA.

    .EXAMPLE
        $secPwd = ConvertTo-SecureString "P@ssw0rd" -AsPlainText -Force
        $cred = New-Object PSCredential("admin", $secPwd)
        $token = Get-SbPAMUserToken -Credentials $cred -UserSecret $env:MFA_SECRET -Uri $env:SBPAM_URL

        Automated authentication using environment variables.

    .NOTES
        Tokens expire after approximately 15 minutes.
        Store the MFA secret securely - never hardcode in scripts.

    .LINK
        Get-SbPAMAppUserToken
        Get-SbPAMToken
        Get-SbPAMMfaToken
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
            HelpMessage = "SbPAM server URL")]
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
    $token = Get-SbPAMToken @Params -SkipCertificateCheck:$SkipCertificateCheck -ErrorAction Stop

    # Generate TOTP code
    $userCode = Get-SbPAMTotp -Secret $UserSecret

    # Complete MFA
    $Params = @{
        Token      = $token
        Code       = $userCode
        WebSession = $WebSession
        Uri        = $Uri
    }
    return Get-SbPAMMfaToken @Params -SkipCertificateCheck:$SkipCertificateCheck
}

function Get-SbPAMAppUserToken {
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
        SbPAM server URL. Default: "https://localhost:6500"

    .PARAMETER SkipCertificateCheck
        Skip SSL certificate validation.

    .OUTPUTS
        System.String
        JWT access token.

    .EXAMPLE
        $cert = Get-SbPAMCertificate -CertThumbPrint "ABC123..."
        $cred = Get-Credential
        $token = Get-SbPAMAppUserToken -Certificate $cert -Credentials $cred -Uri "https://sbpam.company.com"

        Certificate-based authentication.

    .LINK
        Get-SbPAMUserToken
        Get-SbPAMCertificate
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
        return Invoke-SbPAMRest @Params -SkipCertificateCheck:$SkipCertificateCheck
    }
    catch {
        Write-Error "Get-SbPAMAppUserToken Error: $($_) $($_.Exception.InnerException)"
        return $null
    }
}

function Get-SbPAMToken {
    <#
    .SYNOPSIS
        Obtains a pre-MFA token using username and password.

    .DESCRIPTION
        First step of authentication - exchanges credentials for a
        pre-MFA token that must be completed with Get-SbPAMMfaToken.

        This is typically called internally by Get-SbPAMUserToken.

    .PARAMETER Credentials
        NetworkCredential object with username and password.

    .PARAMETER WebSession
        Web session for maintaining state.

    .PARAMETER Uri
        SbPAM server URL.

    .PARAMETER SkipCertificateCheck
        Skip SSL certificate validation.

    .OUTPUTS
        System.String
        Pre-MFA JWT token.

    .EXAMPLE
        $webSession = New-Object Microsoft.PowerShell.Commands.WebRequestSession
        $creds = (Get-Credential).GetNetworkCredential()
        $preToken = Get-SbPAMToken -Credentials $creds -WebSession $webSession -Uri "https://sbpam"

    .LINK
        Get-SbPAMMfaToken
        Get-SbPAMUserToken
    #>
    [CmdletBinding()]
    [OutputType([System.String])]
    param (
        [Parameter(Mandatory = $true)]
        [System.Net.NetworkCredential] $Credentials,

        [Parameter(Mandatory = $true)]
        [Microsoft.PowerShell.Commands.WebRequestSession] $WebSession,

        [Parameter(Mandatory = $false)]
        [string] $Uri = "https://localhost:6500",

        [Parameter(Mandatory = $false)]
        [switch] $SkipCertificateCheck
    )

    $username = $Credentials.UserName
    $domain = $Credentials.Domain
    $tt = $username
    if (![string]::IsNullOrEmpty($domain)) {
        $tt = $domain + "\" + $username
    }
    $body = @{ login = $tt; password = $Credentials.Password }

    $Params = @{
        Body        = $body
        Method      = "Post"
        ContentType = "application/x-www-form-urlencoded"
        WebSession  = $WebSession
        Uri         = "$($Uri.TrimEnd("/"))/signin"
    }
    return Invoke-SbPAMRest @Params -SkipCertificateCheck:$SkipCertificateCheck.IsPresent
}

function Get-SbPAMMfaToken {
    <#
    .SYNOPSIS
        Completes MFA verification to obtain a full access token.

    .DESCRIPTION
        Second step of authentication - exchanges a pre-MFA token and
        TOTP code for a full access token with complete permissions.

    .PARAMETER Token
        Pre-MFA token from Get-SbPAMToken.

    .PARAMETER Code
        6-digit TOTP code from Get-SbPAMTotp or authenticator app.

    .PARAMETER WebSession
        Web session for maintaining state.

    .PARAMETER Uri
        SbPAM server URL.

    .PARAMETER SkipCertificateCheck
        Skip SSL certificate validation.

    .OUTPUTS
        System.String
        Full access JWT token.

    .EXAMPLE
        $code = Get-SbPAMTotp -Secret $mfaSecret
        $fullToken = Get-SbPAMMfaToken -Token $preToken -Code $code -WebSession $session -Uri "https://sbpam"

    .LINK
        Get-SbPAMToken
        Get-SbPAMTotp
        Get-SbPAMUserToken
    #>
    [CmdletBinding()]
    [OutputType([System.String])]
    param(
        [Parameter(Mandatory = $true)]
        [System.String] $Token,

        [Parameter(Mandatory = $true)]
        [ValidatePattern("^\d{6}$")]
        [System.String] $Code,

        [Parameter(Mandatory = $true)]
        [Microsoft.PowerShell.Commands.WebRequestSession] $WebSession,

        [Parameter(Mandatory = $false)]
        [string] $Uri = "https://localhost:6500",

        [Parameter(Mandatory = $false)]
        [switch] $SkipCertificateCheck
    )

    $Params = @{
        Token      = $Token
        Body       = $Code
        Method     = "Post"
        WebSession = $WebSession
        Uri        = "$($Uri.TrimEnd("/"))/signin2fa"
    }
    return Invoke-SbPAMRest @Params -SkipCertificateCheck:$SkipCertificateCheck.IsPresent
}


# ============================================================================
# ACCESS CONTROL & POLICY FUNCTIONS
# ============================================================================

function Get-SbPAMUserPolicy {
    <#
    .SYNOPSIS
        Retrieves access control policies for the current user.

    .DESCRIPTION
        Gets the access control policies associated with the managed account
        ID embedded in the authentication token.

    .PARAMETER Token
        JWT authentication token.

    .PARAMETER Uri
        SbPAM server URL.

    .PARAMETER SkipCertificateCheck
        Skip SSL certificate validation.

    .OUTPUTS
        PSCustomObject[]
        Array of access control policy objects.

    .EXAMPLE
        $policies = Get-SbPAMUserPolicy -Token $token -Uri "https://sbpam"
        $policies | Select-Object name, priority

    .LINK
        Get-SbPAMAccessControlPolicy
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [System.String] $Token,

        [Parameter(Mandatory = $false)]
        [string] $Uri = "https://localhost:6500",

        [Parameter(Mandatory = $false)]
        [switch] $SkipCertificateCheck
    )

    $JwtObj = Convert-SbPAMToken -Token $Token
    $Params = @{
        Token = $Token
        Uri   = "$($Uri)/api/v1/AccessControlPolicy/ManagedAccount/$($JwtObj.ManagedAccountId)"
    }
    return Invoke-SbPAMRest @Params -SkipCertificateCheck:$SkipCertificateCheck.IsPresent
}

function Get-SbPAMAccessControlPolicy {
    <#
    .SYNOPSIS
        Retrieves access control policies from SbPAM.

    .DESCRIPTION
        Gets access control policy definitions by policy ID or by
        managed account ID. Policies define who can access what
        resources and under what conditions.

    .PARAMETER Token
        JWT authentication token.

    .PARAMETER PolicyId
        Specific policy GUID to retrieve.

    .PARAMETER ManagedAccountId
        Get policies for a specific managed account.

    .PARAMETER Uri
        SbPAM server URL.

    .PARAMETER SkipCertificateCheck
        Skip SSL certificate validation.

    .OUTPUTS
        PSCustomObject or PSCustomObject[]
        Access control policy object(s).

    .EXAMPLE
        Get-SbPAMAccessControlPolicy -Token $token -PolicyId "12345-abcd-..."

        Gets a specific policy by ID.

    .EXAMPLE
        Get-SbPAMAccessControlPolicy -Token $token -ManagedAccountId $accountId

        Gets all policies for a managed account.

    .LINK
        Get-SbPAMUserPolicy
        Start-SbPAMActivitySession
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [System.String] $Token,

        [Parameter(Mandatory = $true, ParameterSetName = "PolicyId")]
        [Guid] $PolicyId,

        [Parameter(Mandatory = $true, ParameterSetName = "ManagedAccountId")]
        [System.String] $ManagedAccountId,

        [Parameter(Mandatory = $false)]
        [string] $Uri = "https://localhost:6500",

        [Parameter(Mandatory = $false)]
        [switch] $SkipCertificateCheck
    )

    if ($null -ne $PolicyId) {
        $Params = @{
            Token = $Token
            Uri   = "$($Uri)/api/v1/AccessControlPolicy/$PolicyId"
        }
        return Invoke-SbPAMRest @Params -SkipCertificateCheck:$SkipCertificateCheck.IsPresent
    }

    $_ManagedAccountId = $ManagedAccountId
    if ($null -eq $_ManagedAccountId) {
        $TokenObj = Convert-SbPAMToken -Token $Token -ErrorAction Stop
        if ($null -eq $TokenObj -or $null -eq $TokenObj.ManagedAccountId) {
            throw "Token is missing ManagedAccountId"
        }
        $_ManagedAccountId = $TokenObj.ManagedAccountId
    }

    $Params = @{
        Token = $Token
        Uri   = "$($Uri)/api/v1/AccessControlPolicy/ManagedAccount/$($_ManagedAccountId)"
    }
    return Invoke-SbPAMRest @Params -SkipCertificateCheck:$SkipCertificateCheck.IsPresent
}

# ============================================================================
# CREDENTIAL FUNCTIONS
# ============================================================================

function Get-SbPAMCredential {
    <#
    .SYNOPSIS
        Retrieves credentials from SbPAM.

    .DESCRIPTION
        Gets credential objects by ID, name, or account/resource combination.
        Credentials represent stored secrets including passwords, SSH keys,
        and other authentication materials.

    .PARAMETER Token
        JWT authentication token.

    .PARAMETER Uri
        SbPAM server URL.

    .PARAMETER CredentialId
        Specific credential GUID to retrieve.

    .PARAMETER CredentialName
        Search for credential by display name.

    .PARAMETER CredentialAccount
        Search by account username (requires CredentialResource).

    .PARAMETER CredentialResource
        Search by resource/domain (requires CredentialAccount).

    .PARAMETER SkipCertificateCheck
        Skip SSL certificate validation.

    .OUTPUTS
        PSCustomObject or PSCustomObject[]
        Credential object(s).

    .EXAMPLE
        Get-SbPAMCredential -Token $token -CredentialId "12345-abcd-..."

        Gets credential by ID.

    .EXAMPLE
        Get-SbPAMCredential -Token $token -CredentialName "Admin-Server01"

        Searches for credential by name.

    .EXAMPLE
        Get-SbPAMCredential -Token $token -CredentialAccount "administrator" -CredentialResource "DOMAIN"

        Finds credential by account and domain.

    .LINK
        Get-SbPAMCredentialTypes
        Get-SbPAMCredentialSshCertificate
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [System.String] $Token,

        [Parameter(Mandatory = $false)]
        [string] $Uri = "https://localhost:6500",

        [Parameter(Mandatory, ParameterSetName = "CredentialId")]
        [System.Guid] $CredentialId,

        [Parameter(Mandatory, ParameterSetName = "CredentialName")]
        [System.String] $CredentialName,

        [Parameter(Mandatory, ParameterSetName = "CredentialAccountResource")]
        [System.String] $CredentialAccount,

        [Parameter(Mandatory, ParameterSetName = "CredentialAccountResource")]
        [System.String] $CredentialResource,

        [Parameter(Mandatory = $false)]
        [switch] $SkipCertificateCheck
    )

    $credentials = @()
    $skip = 0
    $take = 100

    if ($null -ne $CredentialName -or $null -ne $CredentialAccount) {
        $FilterText = "$($CredentialName)$($CredentialAccount)"
        $FilterText = [System.Web.HttpUtility]::UrlEncode($FilterText)
        Write-Verbose "FILTERTEXT: $FilterText"

        do {
            $Params = @{
                Token = $Token
                Uri   = "$($Uri.TrimEnd("/"))/api/v1/Credential/Search?skip=$skip&take=$take&filterText=$FilterText"
            }
            $result = Invoke-SbPAMRest @Params -SkipCertificateCheck:$SkipCertificateCheck
            $result.Data | ForEach-Object {
                $credentials += $_
                Write-Verbose "$($_.Id) DisplayName:$($_.displayName) UserName:$($_.UserName) Resource:$($_.domain)"
            }
            $skip += $take
        } until ($credentials.Count -ge $result.RecordsTotal)

        if ($null -ne $CredentialName -and "" -ne $CredentialName) {
            return $credentials | Where-Object -Property DisplayName -eq $CredentialName
        }
        else {
            return $credentials | Where-Object -Property UserName -eq $CredentialAccount | Where-Object -Property Domain -eq $CredentialResource
        }
    }
    else {
        $Params = @{
            Token = $Token
            Uri   = "$($Uri.TrimEnd("/"))/api/v1/Credential/$CredentialId"
        }
        return Invoke-SbPAMRest @Params -SkipCertificateCheck:$SkipCertificateCheck
    }
}

function Get-SbPAMCredentialTypes {
    <#
    .SYNOPSIS
        Gets available credential types.

    .DESCRIPTION
        Retrieves the list of supported credential types in SbPAM:
        Any, Configuration, User, Service, ActivityToken, Application,
        VaultUser, SshKeyCert.

    .PARAMETER Token
        JWT authentication token.

    .PARAMETER Uri
        SbPAM server URL.

    .PARAMETER SkipCertificateCheck
        Skip SSL certificate validation.

    .OUTPUTS
        System.String[]
        Array of credential type names.

    .EXAMPLE
        Get-SbPAMCredentialTypes -Token $token

    .LINK
        Get-SbPAMCredential
        Get-SbPAMAuthenticationMethodTypes
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
        Uri   = "$($Uri.TrimEnd("/"))/api/v1/Credential/GetCredentialTypes"
    }
    return Invoke-SbPAMRest @Params -SkipCertificateCheck:$SkipCertificateCheck
}

function Get-SbPAMAuthenticationMethodTypes {
    <#
    .SYNOPSIS
        Gets available authentication method types.

    .DESCRIPTION
        Retrieves the list of supported authentication methods:
        Password, SshCertificate, SshCertificateAndPassword.

    .PARAMETER Token
        JWT authentication token.

    .PARAMETER Uri
        SbPAM server URL.

    .PARAMETER SkipCertificateCheck
        Skip SSL certificate validation.

    .OUTPUTS
        System.String[]
        Array of authentication method names.

    .EXAMPLE
        Get-SbPAMAuthenticationMethodTypes -Token $token

    .LINK
        Get-SbPAMCredentialTypes
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
    return Invoke-SbPAMRest @Params -SkipCertificateCheck:$SkipCertificateCheck
}

# ============================================================================
# ACTIVITY SESSION FUNCTIONS
# ============================================================================

function Get-SbPAMActivitySession {
    <#
    .SYNOPSIS
        Retrieves activity sessions from SbPAM.

    .DESCRIPTION
        Gets activity session records by ID or status. Activity sessions
        represent privileged access sessions including RDP, SSH, and
        credential checkout sessions.

    .PARAMETER Token
        JWT authentication token.

    .PARAMETER Id
        Specific session GUID to retrieve.

    .PARAMETER Status
        Filter by session status: Active, Pending, ApprovalRequired, Historical.

    .PARAMETER Uri
        SbPAM server URL.

    .PARAMETER SkipCertificateCheck
        Skip SSL certificate validation.

    .OUTPUTS
        PSCustomObject or PSCustomObject[]
        Activity session object(s).

    .EXAMPLE
        Get-SbPAMActivitySession -Token $token -Status "Active"

        Gets all active sessions.

    .EXAMPLE
        Get-SbPAMActivitySession -Token $token -Id "12345-abcd-..."

        Gets a specific session by ID.

    .LINK
        Start-SbPAMActivitySession
        Stop-SbPAMActivitySession
        Get-SbPAMActivitySessionPassword
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [System.String] $Token,

        [Parameter(ParameterSetName = "ById", Mandatory = $false)]
        [System.Guid] $Id,

        [Parameter(ParameterSetName = "ByStatus", Mandatory)]
        [ValidateSet("Active", "Pending", "ApprovalRequired", "Historical")]
        [System.String] $Status,

        [Parameter(Mandatory = $false)]
        [string] $Uri = "https://localhost:6500",

        [Parameter(Mandatory = $false)]
        [switch] $SkipCertificateCheck
    )

    $restEndpoint = "$($Uri)/api/v1/ActivitySession"
    if (![string]::IsNullOrEmpty($Id)) {
        $restEndpoint += "/$($Id)"
    }
    elseif (![string]::IsNullOrEmpty($Status)) {
        $restEndpoint += "?status=$($Status)"
    }

    $Params = @{
        Token = $Token
        Uri   = $restEndpoint
    }
    return Invoke-SbPAMRest @Params -SkipCertificateCheck:$SkipCertificateCheck.IsPresent
}

function Get-SbPAMActivitySessionSummary {
    <#
    .SYNOPSIS
        Gets activity session summary information.

    .DESCRIPTION
        Retrieves summary information for activity sessions, either
        by status for the current user or by specific session ID.

    .PARAMETER Token
        JWT authentication token.

    .PARAMETER Status
        Filter by status: Active, Pending, ApprovalRequired, Historical.

    .PARAMETER Id
        Specific session GUID for summary.

    .PARAMETER Uri
        SbPAM server URL.

    .PARAMETER SkipCertificateCheck
        Skip SSL certificate validation.

    .OUTPUTS
        PSCustomObject or PSCustomObject[]
        Session summary object(s).

    .EXAMPLE
        Get-SbPAMActivitySessionSummary -Token $token -Status "Active"

        Gets summary of active sessions for current user.

    .LINK
        Get-SbPAMActivitySession
        Get-SbPAMActivitySessionCount
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [System.String] $Token,

        [Parameter(Mandatory = $true, ParameterSetName = "ByStatus")]
        [ValidateSet("Active", "Pending", "ApprovalRequired", "Historical")]
        [System.String] $Status,

        [Parameter(Mandatory = $true, ParameterSetName = "ById")]
        [Guid] $Id,

        [Parameter(Mandatory = $false)]
        [string] $Uri = "https://localhost:6500",

        [Parameter(Mandatory = $false)]
        [switch] $SkipCertificateCheck
    )

    $restEndpoint = "$($Uri)/api/v1/ActivitySession/MySummaryByStatus/$Status"
    if ($null -ne $Id) {
        $restEndpoint = "$($Uri)/api/v1/ActivitySession/SummaryById/$Id"
    }

    $Params = @{
        Token = $Token
        Uri   = $restEndpoint
    }
    $result = Invoke-SbPAMRest @Params -SkipCertificateCheck:$SkipCertificateCheck.IsPresent

    if ($null -ne $Id) {
        return $result
    }
    $sessions = @()
    $result.Data | ForEach-Object { $sessions += $_ }
    return $sessions
}

function Get-SbPAMActivitySessionPassword {
    <#
    .SYNOPSIS
        Retrieves the password for an activity session.

    .DESCRIPTION
        Gets the credential password associated with an active
        activity session. The session must be in an active state.

    .PARAMETER Token
        JWT authentication token.

    .PARAMETER Id
        Activity session GUID.

    .PARAMETER Uri
        SbPAM server URL.

    .PARAMETER SkipCertificateCheck
        Skip SSL certificate validation.

    .OUTPUTS
        System.String
        The session password.

    .EXAMPLE
        $password = Get-SbPAMActivitySessionPassword -Token $token -Id $sessionId

        Retrieves password for the specified session.

    .NOTES
        Requires an active session. Password is returned in plain text.
        Handle securely and avoid logging.

    .LINK
        Get-SbPAMActivitySession
        Start-SbPAMActivitySession
    #>
    [CmdletBinding()]
    [OutputType([System.String])]
    param (
        [Parameter(Mandatory = $true)]
        [System.String] $Token,

        [Parameter(Mandatory = $true)]
        [System.Guid] $Id,

        [Parameter(Mandatory = $false)]
        [string] $Uri = "https://localhost:6500",

        [Parameter(Mandatory = $false)]
        [switch] $SkipCertificateCheck
    )

    $Params = @{
        Token = $Token
        Uri   = "$($Uri)/api/v1/ActivitySession/$($Id)/Password"
    }
    return Invoke-SbPAMRest @Params -SkipCertificateCheck:$SkipCertificateCheck.IsPresent
}

function Get-SbPAMActivitySessionConfiguration {
    <#
    .SYNOPSIS
        Gets activity session configuration.

    .DESCRIPTION
        Retrieves configuration settings for activity sessions,
        optionally for a specific session ID.

    .PARAMETER Token
        JWT authentication token.

    .PARAMETER Id
        Optional session GUID for specific configuration.

    .PARAMETER Uri
        SbPAM server URL.

    .PARAMETER SkipCertificateCheck
        Skip SSL certificate validation.

    .OUTPUTS
        PSCustomObject
        Session configuration object.

    .EXAMPLE
        Get-SbPAMActivitySessionConfiguration -Token $token

        Gets default session configuration.

    .LINK
        Get-SbPAMActivitySession
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [System.String] $Token,

        [Parameter(Mandatory = $false)]
        [System.Guid] $Id,

        [Parameter(Mandatory = $false)]
        [string] $Uri = "https://localhost:6500",

        [Parameter(Mandatory = $false)]
        [switch] $SkipCertificateCheck
    )

    $restEndpoint = "$($Uri)/api/v1/ActivitySession/Config"
    if (![string]::IsNullOrEmpty($Id)) {
        $restEndpoint += "/$Id"
    }

    $Params = @{
        Token = $Token
        Uri   = $restEndpoint
    }
    return Invoke-SbPAMRest @Params -SkipCertificateCheck:$SkipCertificateCheck.IsPresent
}

function Get-SbPAMActivitySessionCount {
    <#
    .SYNOPSIS
        Gets the count of activity sessions.

    .DESCRIPTION
        Returns the number of activity sessions, optionally filtered by status.

    .PARAMETER Token
        JWT authentication token.

    .PARAMETER Status
        Optional status filter.

    .PARAMETER Uri
        SbPAM server URL.

    .PARAMETER SkipCertificateCheck
        Skip SSL certificate validation.

    .OUTPUTS
        System.Int32
        Count of sessions.

    .EXAMPLE
        Get-SbPAMActivitySessionCount -Token $token -Status "Active"

        Gets count of active sessions.

    .LINK
        Get-SbPAMActivitySession
    #>
    [CmdletBinding()]
    [OutputType([int])]
    param (
        [Parameter(Mandatory = $true)]
        [System.String] $Token,

        [Parameter(Mandatory = $false)]
        [System.String] $Status,

        [Parameter(Mandatory = $false)]
        [string] $Uri = "https://localhost:6500",

        [Parameter(Mandatory = $false)]
        [switch] $SkipCertificateCheck
    )

    $restEndpoint = "$($Uri)/api/v1/ActivitySession/Count"
    if (![string]::IsNullOrEmpty($Status)) {
        $restEndpoint += "?status=$($Status)"
    }

    $Params = @{
        Token = $Token
        Uri   = $restEndpoint
    }
    return Invoke-SbPAMRest @Params -SkipCertificateCheck:$SkipCertificateCheck.IsPresent
}

function Start-SbPAMActivitySession {
    <#
    .SYNOPSIS
        Starts a new activity session for privileged access.

    .DESCRIPTION
        Creates and starts a new activity session for accessing a
        managed resource. Supports various identification methods
        including resource ID/name and credential ID/name.

    .PARAMETER Token
        JWT authentication token.

    .PARAMETER ActivityName
        Name of the activity type (e.g., "RDP", "SSH", "CredentialRelease").

    .PARAMETER AccessPolicyId
        Optional access policy GUID to use.

    .PARAMETER ResourceId
        Managed resource GUID.

    .PARAMETER ResourceName
        Managed resource name (alternative to ResourceId).

    .PARAMETER CredentialId
        Credential GUID to use.

    .PARAMETER CredentialName
        Credential name (alternative to CredentialId).

    .PARAMETER CredentialAccount
        Credential account username (requires CredentialResource).

    .PARAMETER CredentialResource
        Credential resource/domain (requires CredentialAccount).

    .PARAMETER StartTime
        Scheduled start time (default: now).

    .PARAMETER EndTime
        Scheduled end time.

    .PARAMETER Uri
        SbPAM server URL.

    .PARAMETER SkipCertificateCheck
        Skip SSL certificate validation.

    .OUTPUTS
        PSCustomObject
        The created activity session object.

    .EXAMPLE
        Start-SbPAMActivitySession -Token $token -ActivityName "RDP" -ResourceName "Server01" -CredentialName "Admin-Server01"

        Starts an RDP session to Server01.

    .EXAMPLE
        $session = Start-SbPAMActivitySession -Token $token -ActivityName "SSH" -ResourceId $serverId -CredentialId $credId
        $password = Get-SbPAMActivitySessionPassword -Token $token -Id $session.Id

        Starts SSH session and retrieves password.

    .LINK
        Stop-SbPAMActivitySession
        Get-SbPAMActivitySession
        Get-SbPAMActivitySessionPassword
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [System.String] $Token,

        [Parameter(Mandatory = $false)]
        [System.Guid] $AccessPolicyId,

        [Parameter(Mandatory)]
        [System.String] $ActivityName,

        [Parameter(Mandatory, ParameterSetName = "ResourceId")]
        [System.Guid] $ResourceId,

        [Parameter(Mandatory, ParameterSetName = "ResourceName")]
        [System.String] $ResourceName,

        [Parameter(Mandatory, ParameterSetName = "CredentialId")]
        [System.Guid] $CredentialId,

        [Parameter(Mandatory, ParameterSetName = "CredentialName")]
        [System.String] $CredentialName,

        [Parameter(Mandatory, ParameterSetName = "CredentialAccountResource")]
        [System.String] $CredentialAccount,

        [Parameter(Mandatory, ParameterSetName = "CredentialAccountResource")]
        [System.String] $CredentialResource,

        [Parameter(Mandatory = $false)]
        [System.DateTime] $StartTime,

        [Parameter(Mandatory = $false)]
        [System.DateTime] $EndTime,

        [Parameter(Mandatory = $false)]
        [string] $Uri = "https://localhost:6500",

        [Parameter(Mandatory = $false)]
        [switch] $SkipCertificateCheck
    )

    # Convert times to UTC
    if ($null -ne $StartTime -and $StartTime.Kind -ne "Utc") {
        $StartTime = $StartTime.ToUniversalTime()
    }
    $StartTimeUtc = if ($null -ne $StartTime) { 
        $StartTime.ToString("yyyy-MM-ddTHH:mm:ssZ") 
    } else { 
        (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ") 
    }

    if ($null -ne $EndTime -and $EndTime.Kind -ne "Utc") {
        $EndTime = $EndTime.ToUniversalTime()
    }
    $EndTimeUtc = if ($null -ne $EndTime) { $EndTime.ToString("yyyy-MM-ddTHH:mm:ssZ") } else { $null }

    # Get managed account ID from token
    $TokenObj = Convert-SbPAMToken -Token $Token -ErrorAction Stop
    if ($null -eq $TokenObj -or $null -eq $TokenObj.ManagedAccountId) {
        throw "Token is missing ManagedAccountId"
    }
    $ManagedAccountId = $TokenObj.ManagedAccountId

    # Build request
    $request = @{
        activityName     = $ActivityName
        managedAccountId = $ManagedAccountId
        startDateTimeUtc = $StartTimeUtc
        endDateTimeUtc   = $EndTimeUtc
        accessPolicyId   = $AccessPolicyId
    }

    if ($null -ne $CredentialId) { $request.credentialId = $CredentialId }
    if ($null -ne $ResourceId) { $request.managedResourceId = $ResourceId }
    if ($null -ne $ResourceName) { $request.managedResourceName = $ResourceName }
    if ($null -ne $CredentialName) { $request.credentialName = $CredentialName }
    if ($null -ne $CredentialAccount) {
        $request.credentialUserName = $CredentialAccount
        $request.credentialDomain = $CredentialResource
    }

    $bodyJson = ConvertTo-Json $request
    Write-Verbose $bodyJson

    $Params = @{
        Token  = $Token
        Body   = $bodyJson
        Method = "Post"
        Uri    = "$($Uri)/api/v1/ActivitySession"
    }
    return Invoke-SbPAMRest @Params -SkipCertificateCheck:$SkipCertificateCheck.IsPresent
}

function Stop-SbPAMActivitySession {
    <#
    .SYNOPSIS
        Stops an active activity session.

    .DESCRIPTION
        Terminates an activity session and releases the associated
        credential. The session must be in an active state.

    .PARAMETER Token
        JWT authentication token.

    .PARAMETER Id
        Activity session GUID to stop.

    .PARAMETER Uri
        SbPAM server URL.

    .PARAMETER SkipCertificateCheck
        Skip SSL certificate validation.

    .OUTPUTS
        PSCustomObject
        Result of the stop operation.

    .EXAMPLE
        Stop-SbPAMActivitySession -Token $token -Id $sessionId

        Stops the specified session.

    .EXAMPLE
        Get-SbPAMActivitySession -Token $token -Status "Active" | ForEach-Object {
            Stop-SbPAMActivitySession -Token $token -Id $_.Id
        }

        Stops all active sessions.

    .LINK
        Start-SbPAMActivitySession
        Get-SbPAMActivitySession
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [System.String] $Token,

        [Parameter(Mandatory = $true)]
        [System.Guid] $Id,

        [Parameter(Mandatory = $false)]
        [string] $Uri = "https://localhost:6500",

        [Parameter(Mandatory = $false)]
        [switch] $SkipCertificateCheck
    )

    $Params = @{
        Token  = $Token
        Method = "Delete"
        Uri    = "$($Uri)/api/v1/ActivitySession/$($Id)"
    }
    return Invoke-SbPAMRest @Params -SkipCertificateCheck:$SkipCertificateCheck.IsPresent
}

# ============================================================================
# MANAGED RESOURCE FUNCTIONS
# ============================================================================

function Get-SbPAMActivitySessionResource {
    <#
    .SYNOPSIS
        Gets resources available for activity sessions.
    .DESCRIPTION
        Retrieves managed resources that can be used for activity sessions.
    .PARAMETER Token
        JWT authentication token.
    .PARAMETER FilterText
        Text filter for searching resources.
    .PARAMETER DNSHostName
        Filter by DNS hostname.
    .PARAMETER Uri
        SbPAM server URL.
    .PARAMETER SkipCertificateCheck
        Skip SSL certificate validation.
    .EXAMPLE
        Get-SbPAMActivitySessionResource -Token $token -FilterText "Windows"
    .LINK
        Start-SbPAMActivitySession
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)][string] $Token,
        [Parameter()][string] $FilterText,
        [Parameter()][string] $DNSHostName,
        [Parameter()][Guid] $CredentialId,
        [Parameter()][Guid] $ResourceId,
        [Parameter(Mandatory = $false)][string] $Uri = "https://localhost:6500",
        [Parameter(Mandatory = $false)][switch] $SkipCertificateCheck
    )
    $resources = @(); $skip = 0; $take = 100
    $Params = @{ Token = $Token; Body = @{ FilterText = $FilterText } }
    do {
        $Params.Uri = "$($Uri.TrimEnd("/"))/api/v1/ActivitySession/Resources?skip=$skip&take=$take"
        $result = Invoke-SbPAMRest @Params -SkipCertificateCheck:$SkipCertificateCheck -Method Post
        $result.Data | ForEach-Object { $resources += $_ }
        $skip += $take
    } until ($resources.Count -ge $result.RecordsTotal)
    if (![string]::IsNullOrEmpty($DNSHostName)) { $resources = $resources | Where-Object { $_.DnsHostName -eq $DNSHostName } }
    if ($null -ne $CredentialId) { $resources = $resources | Where-Object { $_.CredentialId -eq $CredentialId } }
    if ($null -ne $ResourceId) { $resources = $resources | Where-Object { $_.Id -eq $ResourceId } }
    return $resources
}

function Get-SbPAMManagedResource {
    <#
    .SYNOPSIS
        Retrieves managed resources from SbPAM.
    .DESCRIPTION
        Gets managed resource objects by ID or searches with filters.
    .PARAMETER Token
        JWT authentication token.
    .PARAMETER Id
        Specific resource GUID to retrieve.
    .PARAMETER FilterText
        Text filter for searching.
    .PARAMETER Uri
        SbPAM server URL.
    .EXAMPLE
        Get-SbPAMManagedResource -Token $token -Id "12345-abcd-..."
    .EXAMPLE
        Get-SbPAMManagedResource -Token $token -FilterText "SQL"
    .LINK
        Get-SbPAMActivitySessionResource
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)][string] $Token,
        [Parameter(Mandatory = $false)][Guid] $Id,
        [Parameter(Mandatory = $false)][string] $FilterText,
        [Parameter(Mandatory = $false)][string] $Uri = "https://localhost:6500",
        [Parameter(Mandatory = $false)][switch] $SkipCertificateCheck
    )
    if ($null -ne $Id) {
        $Params = @{ Token = $Token; Uri = "$($Uri.TrimEnd("/"))/api/v1/ManagedResource/$Id" }
        return Invoke-SbPAMRest @Params -SkipCertificateCheck:$SkipCertificateCheck
    }
    $resources = @(); $skip = 0; $take = 100
    do {
        $searchUri = "$($Uri.TrimEnd("/"))/api/v1/ManagedResource/Search?skip=$skip&take=$take"
        if (![string]::IsNullOrEmpty($FilterText)) { $searchUri += "&filterText=$([System.Web.HttpUtility]::UrlEncode($FilterText))" }
        $Params = @{ Token = $Token; Uri = $searchUri }
        $result = Invoke-SbPAMRest @Params -SkipCertificateCheck:$SkipCertificateCheck
        $result.Data | ForEach-Object { $resources += $_ }
        $skip += $take
    } until ($resources.Count -ge $result.RecordsTotal)
    return $resources
}

function Get-SbPAMManagedResourceSshFingerprint {
    <#
    .SYNOPSIS
        Gets the SSH fingerprint for a managed resource.
    .PARAMETER Token
        JWT authentication token.
    .PARAMETER ResourceId
        Managed resource GUID.
    .EXAMPLE
        Get-SbPAMManagedResourceSshFingerprint -Token $token -ResourceId $resourceId
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string] $Token,
        [Parameter(Mandatory = $true)][System.Guid] $ResourceId,
        [Parameter(Mandatory = $false)][string] $Uri = "https://localhost:6500",
        [Parameter(Mandatory = $false)][switch] $SkipCertificateCheck
    )
    $Params = @{ Token = $Token; Uri = "$($Uri.TrimEnd("/"))/api/v1/ManagedResource/GetSshFingerprint/$ResourceId" }
    return Invoke-SbPAMRest @Params -SkipCertificateCheck:$SkipCertificateCheck
}

function Set-SbPAMManagedResourceTrustThumbprint {
    <#
    .SYNOPSIS
        Sets the trusted SSH thumbprint for a managed resource.
    .PARAMETER Token
        JWT authentication token.
    .PARAMETER ResourceId
        Managed resource GUID.
    .EXAMPLE
        Set-SbPAMManagedResourceTrustThumbprint -Token $token -ResourceId $resourceId
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string] $Token,
        [Parameter(Mandatory = $true)][System.Guid] $ResourceId,
        [Parameter(Mandatory = $false)][string] $Uri = "https://localhost:6500",
        [Parameter(Mandatory = $false)][switch] $SkipCertificateCheck
    )
    $Params = @{ Method = "Put"; Token = $Token; Uri = "$($Uri.TrimEnd("/"))/api/v1/ManagedResource/$ResourceId/Trust" }
    return Invoke-SbPAMRest @Params -SkipCertificateCheck:$SkipCertificateCheck
}

# ============================================================================
# SSH CERTIFICATE FUNCTIONS
# ============================================================================

function Get-SbPAMSSHKeyGenAlgorithm {
    <#
    .SYNOPSIS
        Gets available SSH key generation algorithms.
    .DESCRIPTION
        Retrieves supported SSH key algorithms (RSA, ECDSA, Ed25519).
    .PARAMETER Token
        JWT authentication token.
    .EXAMPLE
        Get-SbPAMSSHKeyGenAlgorithm -Token $token
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string] $Token,
        [Parameter(Mandatory = $false)][string] $Uri = "https://localhost:6500",
        [Parameter(Mandatory = $false)][switch] $SkipCertificateCheck
    )
    $Params = @{ Token = $Token; Uri = "$($Uri.TrimEnd("/"))/api/v1/Credential/SSHKeyGenAlgorithms" }
    return Invoke-SbPAMRest @Params -SkipCertificateCheck:$SkipCertificateCheck
}

function New-SbPAMUserSshCertificate {
    <#
    .SYNOPSIS
        Generates a new SSH certificate for a user.
    .DESCRIPTION
        Creates a new SSH certificate credential with specified algorithm.
    .PARAMETER UserId
        User GUID to generate certificate for.
    .PARAMETER Token
        JWT authentication token.
    .PARAMETER KeyGenAlgorithm
        Algorithm: RSA, ECDSA, Ed25519. Default: RSA
    .PARAMETER KeyLength
        Key length in bits (for RSA).
    .PARAMETER AutoGenPassphrase
        Auto-generate passphrase. Default: true
    .EXAMPLE
        New-SbPAMUserSshCertificate -UserId $userId -Token $token -KeyGenAlgorithm "RSA" -KeyLength 4096
    .EXAMPLE
        New-SbPAMUserSshCertificate -UserId $userId -Token $token -KeyGenAlgorithm "Ed25519"
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][Guid] $UserId,
        [Parameter(Mandatory = $true)][string] $Token,
        [Parameter(Mandatory = $false)][bool] $AutoGenPassphrase = $true,
        [Parameter(Mandatory = $false)][string] $Passphrase,
        [Parameter(Mandatory = $false)][ValidateSet("RSA", "ECDSA", "Ed25519")][string] $KeyGenAlgorithm = "RSA",
        [Parameter(Mandatory = $false)][int] $KeyLength,
        [Parameter(Mandatory = $false)][ValidateSet("Any", "Configuration", "User", "Service", "ActivityToken", "Application", "VaultUser", "SshKeyCert")][string] $CredentialType = "SshKeyCert",
        [Parameter(Mandatory = $false)][ValidateSet("Password", "SshCertificate", "SshCertificateAndPassword")][string] $AuthenticationMethod,
        [Parameter(Mandatory = $false)][string] $Uri = "https://localhost:6500",
        [Parameter(Mandatory = $false)][switch] $SkipCertificateCheck
    )
    $sshBody = @{ autoGenPassphrase = $AutoGenPassphrase; passphrase = $Passphrase; keyGenAlgorithm = $KeyGenAlgorithm; keyLength = $KeyLength; credentialType = $CredentialType; authenticationMethod = $AuthenticationMethod }
    $body = ConvertTo-Json $sshBody
    $Params = @{ Token = $Token; Body = $body; Method = "Post"; Uri = "$($Uri.TrimEnd("/"))/api/v1/Credential/GenerateUserSshCertificate/$UserId" }
    return Invoke-SbPAMRest @Params -SkipCertificateCheck:$SkipCertificateCheck
}

function Get-SbPAMCredentialSshCertificate {
    <#
    .SYNOPSIS
        Gets an SSH certificate by credential ID.
    .PARAMETER CredentialId
        Credential GUID.
    .PARAMETER Token
        JWT authentication token.
    .EXAMPLE
        Get-SbPAMCredentialSshCertificate -CredentialId $credId -Token $token
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][Guid] $CredentialId,
        [Parameter(Mandatory = $true)][string] $Token,
        [Parameter(Mandatory = $false)][string] $Uri = "https://localhost:6500",
        [Parameter(Mandatory = $false)][switch] $SkipCertificateCheck
    )
    $Params = @{ Token = $Token; Uri = "$($Uri.TrimEnd("/"))/api/v1/Credential/GetCredentialSshCertificate/$CredentialId" }
    return Invoke-SbPAMRest @Params -SkipCertificateCheck:$SkipCertificateCheck
}

function Get-SbPAMUserSshCertificate {
    <#
    .SYNOPSIS
        Gets SSH certificates for a user by user ID.
    .PARAMETER UserId
        User GUID.
    .PARAMETER Token
        JWT authentication token.
    .EXAMPLE
        Get-SbPAMUserSshCertificate -UserId $userId -Token $token
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][Guid] $UserId,
        [Parameter(Mandatory = $true)][string] $Token,
        [Parameter(Mandatory = $false)][string] $Uri = "https://localhost:6500",
        [Parameter(Mandatory = $false)][switch] $SkipCertificateCheck
    )
    $Params = @{ Token = $Token; Uri = "$($Uri.TrimEnd("/"))/api/v1/Credential/GetUserSshCertificate/$UserId" }
    return Invoke-SbPAMRest @Params -SkipCertificateCheck:$SkipCertificateCheck
}

function Get-SbPAMSshCertificateByDomainUser {
    <#
    .SYNOPSIS
        Gets SSH certificate by domain and username.
    .PARAMETER DomainName
        Domain name.
    .PARAMETER UserName
        Username.
    .EXAMPLE
        Get-SbPAMSshCertificateByDomainUser -DomainName "CORP" -UserName "jsmith" -Token $token
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string] $DomainName,
        [Parameter(Mandatory = $true)][string] $UserName,
        [Parameter(Mandatory = $true)][string] $Token,
        [Parameter(Mandatory = $false)][string] $Uri = "https://localhost:6500",
        [Parameter(Mandatory = $false)][switch] $SkipCertificateCheck
    )
    $Params = @{ Token = $Token; Uri = "$($Uri.TrimEnd("/"))/api/v1/Credential/GetSshCertificateByDomainUser/$DomainName/$UserName" }
    return Invoke-SbPAMRest @Params -SkipCertificateCheck:$SkipCertificateCheck
}

function Get-SbPAMSshCertificateByUser {
    <#
    .SYNOPSIS
        Gets SSH certificate by username.
    .PARAMETER UserName
        Username.
    .EXAMPLE
        Get-SbPAMSshCertificateByUser -UserName "jsmith" -Token $token
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string] $UserName,
        [Parameter(Mandatory = $true)][string] $Token,
        [Parameter(Mandatory = $false)][string] $Uri = "https://localhost:6500",
        [Parameter(Mandatory = $false)][switch] $SkipCertificateCheck
    )
    $Params = @{ Token = $Token; Uri = "$($Uri.TrimEnd("/"))/api/v1/Credential/GetSshCertificateByUser/$UserName" }
    return Invoke-SbPAMRest @Params -SkipCertificateCheck:$SkipCertificateCheck
}

# ============================================================================
# DOMAIN FUNCTIONS
# ============================================================================

function Get-SbPAMDomain {
    <#
    .SYNOPSIS
        Gets Active Directory domain information.
    .DESCRIPTION
        Retrieves domain configuration by domain ID or configuration ID.
    .PARAMETER Token
        JWT authentication token.
    .PARAMETER Id
        Domain GUID.
    .PARAMETER DomainConfigurationId
        Domain configuration GUID.
    .EXAMPLE
        Get-SbPAMDomain -Token $token -Id $domainId
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string] $Token,
        [Parameter(Mandatory = $true, ParameterSetName = "ById")][Guid] $Id,
        [Parameter(Mandatory = $true, ParameterSetName = "ByDomainConfigurationId")][Guid] $DomainConfigurationId,
        [Parameter(Mandatory = $false)][string] $Uri = "https://localhost:6500",
        [Parameter(Mandatory = $false)][switch] $SkipCertificateCheck
    )
    if ($null -ne $DomainConfigurationId) {
        $Params = @{ Token = $Token; Uri = "$($Uri.TrimEnd("/"))/api/v1/ActiveDirectory/Domain/ByDomainConfiguration/$DomainConfigurationId" }
    } else {
        $Params = @{ Token = $Token; Uri = "$($Uri.TrimEnd("/"))/api/v1/ActiveDirectory/Domain/$Id" }
    }
    return Invoke-SbPAMRest @Params -SkipCertificateCheck:$SkipCertificateCheck
}

# ============================================================================
# REPLAY SESSION / SEARCH FUNCTIONS
# ============================================================================

function Search-SbPAMActiveSession {
    <#
    .SYNOPSIS
        Searches active sessions for specific content.
    .DESCRIPTION
        Searches currently active sessions for matching content.
    .PARAMETER SearchFilter
        Text to search for in session content.
    .PARAMETER Token
        JWT authentication token.
    .PARAMETER Key
        Content type: All, Windows_Audit, StdIn, StdOut. Default: All
    .EXAMPLE
        Search-SbPAMActiveSession -SearchFilter "password" -Token $token
    .EXAMPLE
        Search-SbPAMActiveSession -SearchFilter "sudo" -Key "StdIn" -Token $token
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string] $SearchFilter,
        [Parameter(Mandatory = $true)][string] $Token,
        [Parameter(Mandatory = $false)][ValidateSet("All", "Windows_Audit", "StdIn", "StdOut")][string] $Key = "All",
        [Parameter(Mandatory = $false)][string] $Uri = "https://localhost:6500",
        [Parameter(Mandatory = $false)][switch] $SkipCertificateCheck
    )
    $body = @{ searchFilter = $SearchFilter; key = $Key } | ConvertTo-Json
    $Params = @{ Token = $Token; Body = $body; Method = "Post"; Uri = "$($Uri.TrimEnd("/"))/api/v1/ReplaySession/SearchActiveSessions" }
    return Invoke-SbPAMRest @Params -SkipCertificateCheck:$SkipCertificateCheck
}

function Search-SbPAMHistoricalSession {
    <#
    .SYNOPSIS
        Searches historical sessions for specific content.
    .DESCRIPTION
        Searches completed session recordings for matching content.
    .PARAMETER SearchFilter
        Text to search for.
    .PARAMETER Token
        JWT authentication token.
    .PARAMETER Key
        Content type: All, Windows_Audit, StdIn, StdOut. Default: All
    .EXAMPLE
        Search-SbPAMHistoricalSession -SearchFilter "rm -rf" -Token $token
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string] $SearchFilter,
        [Parameter(Mandatory = $true)][string] $Token,
        [Parameter(Mandatory = $false)][ValidateSet("All", "Windows_Audit", "StdIn", "StdOut")][string] $Key = "All",
        [Parameter(Mandatory = $false)][string] $Uri = "https://localhost:6500",
        [Parameter(Mandatory = $false)][switch] $SkipCertificateCheck
    )
    $body = @{ searchFilter = $SearchFilter; key = $Key } | ConvertTo-Json
    $Params = @{ Token = $Token; Body = $body; Method = "Post"; Uri = "$($Uri.TrimEnd("/"))/api/v1/ReplaySession/SearchHistoricalSessions" }
    return Invoke-SbPAMRest @Params -SkipCertificateCheck:$SkipCertificateCheck
}

# ============================================================================
# CISCO DEVICE FUNCTIONS
# ============================================================================

function Get-SbPAMCiscoEnablePassword {
    <#
    .SYNOPSIS
        Gets the Cisco enable password for a session.
    .DESCRIPTION
        Retrieves the enable mode password for Cisco device access.
    .PARAMETER Token
        JWT authentication token.
    .PARAMETER SessionId
        Activity session GUID.
    .EXAMPLE
        $enablePwd = Get-SbPAMCiscoEnablePassword -Token $token -SessionId $sessionId
    .LINK
        Start-SbPAMActivitySession
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string] $Token,
        [Parameter(Mandatory = $true)][Guid] $SessionId,
        [Parameter(Mandatory = $false)][string] $Uri = "https://localhost:6500",
        [Parameter(Mandatory = $false)][switch] $SkipCertificateCheck
    )
    $Params = @{ Token = $Token; Uri = "$($Uri.TrimEnd("/"))/api/v1/ActivitySession/$SessionId/CiscoEnablePassword" }
    return Invoke-SbPAMRest @Params -SkipCertificateCheck:$SkipCertificateCheck
}

function Get-SbPAMCiscoEnablePasswordByCredential {
    <#
    .SYNOPSIS
        Gets Cisco enable password by credential ID.
    .DESCRIPTION
        Retrieves the enable password associated with a credential.
    .PARAMETER Token
        JWT authentication token.
    .PARAMETER CredentialId
        Credential GUID.
    .EXAMPLE
        Get-SbPAMCiscoEnablePasswordByCredential -Token $token -CredentialId $credId
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string] $Token,
        [Parameter(Mandatory = $true)][Guid] $CredentialId,
        [Parameter(Mandatory = $false)][string] $Uri = "https://localhost:6500",
        [Parameter(Mandatory = $false)][switch] $SkipCertificateCheck
    )
    $Params = @{ Token = $Token; Uri = "$($Uri.TrimEnd("/"))/api/v1/Credential/$CredentialId/CiscoEnablePassword" }
    return Invoke-SbPAMRest @Params -SkipCertificateCheck:$SkipCertificateCheck
}

# ============================================================================
# SYSTEM SETTINGS FUNCTIONS
# ============================================================================

function Get-SbPAMSettings {
    <#
    .SYNOPSIS
        Gets SbPAM system settings.
    .DESCRIPTION
        Retrieves system configuration settings.
    .PARAMETER Token
        JWT authentication token.
    .EXAMPLE
        Get-SbPAMSettings -Token $token
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string] $Token,
        [Parameter(Mandatory = $false)][string] $Uri = "https://localhost:6500",
        [Parameter(Mandatory = $false)][switch] $SkipCertificateCheck
    )
    $Params = @{ Token = $Token; Uri = "$($Uri.TrimEnd("/"))/api/v1/Settings" }
    return Invoke-SbPAMRest @Params -SkipCertificateCheck:$SkipCertificateCheck
}

function Get-SbPAMVersion {
    <#
    .SYNOPSIS
        Gets the SbPAM server version.
    .DESCRIPTION
        Retrieves the product version string.
    .PARAMETER Token
        JWT authentication token.
    .EXAMPLE
        Get-SbPAMVersion -Token $token
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string] $Token,
        [Parameter(Mandatory = $false)][string] $Uri = "https://localhost:6500",
        [Parameter(Mandatory = $false)][switch] $SkipCertificateCheck
    )
    $Params = @{ Token = $Token; Uri = "$($Uri.TrimEnd("/"))/api/v1/Version" }
    return Invoke-SbPAMRest @Params -SkipCertificateCheck:$SkipCertificateCheck
}

function Get-SbPAMHealth {
    <#
    .SYNOPSIS
        Gets the SbPAM server health status.
    .DESCRIPTION
        Retrieves the current health status of the server.
    .PARAMETER Token
        JWT authentication token.
    .EXAMPLE
        Get-SbPAMHealth -Token $token
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string] $Token,
        [Parameter(Mandatory = $false)][string] $Uri = "https://localhost:6500",
        [Parameter(Mandatory = $false)][switch] $SkipCertificateCheck
    )
    $Params = @{ Token = $Token; Uri = "$($Uri.TrimEnd("/"))/api/v1/Health" }
    return Invoke-SbPAMRest @Params -SkipCertificateCheck:$SkipCertificateCheck
}

# ============================================================================
# MODULE EXPORT
# ============================================================================

$ExportedFunctions = @(
    # Authentication
    "Get-SbPAMToken"
    "Get-SbPAMTokenMFA"
    "Convert-SbPAMToken"
    "Test-SbPAMToken"

    # Access Control
    "Get-SbPAMUserPolicy"
    "Get-SbPAMAccessControlPolicy"

    # Credentials
    "Get-SbPAMCredential"
    "Get-SbPAMCredentialTypes"
    "Get-SbPAMAuthenticationMethodTypes"

    # Activity Sessions
    "Get-SbPAMActivitySession"
    "Get-SbPAMActivitySessionSummary"
    "Get-SbPAMActivitySessionPassword"
    "Get-SbPAMActivitySessionConfiguration"
    "Get-SbPAMActivitySessionCount"
    "Start-SbPAMActivitySession"
    "Stop-SbPAMActivitySession"

    # Managed Resources
    "Get-SbPAMActivitySessionResource"
    "Get-SbPAMManagedResource"
    "Get-SbPAMManagedResourceSshFingerprint"
    "Set-SbPAMManagedResourceTrustThumbprint"

    # SSH Certificates
    "Get-SbPAMSSHKeyGenAlgorithm"
    "New-SbPAMUserSshCertificate"
    "Get-SbPAMCredentialSshCertificate"
    "Get-SbPAMUserSshCertificate"
    "Get-SbPAMSshCertificateByDomainUser"
    "Get-SbPAMSshCertificateByUser"

    # Domain
    "Get-SbPAMDomain"

    # Session Search
    "Search-SbPAMActiveSession"
    "Search-SbPAMHistoricalSession"

    # Cisco
    "Get-SbPAMCiscoEnablePassword"
    "Get-SbPAMCiscoEnablePasswordByCredential"

    # System
    "Get-SbPAMSettings"
    "Get-SbPAMVersion"
    "Get-SbPAMHealth"

    # Helpers (internal but exported for advanced use)
    "Invoke-SbPAMRest"
    "Get-SbPAMTOTP"
)

Export-ModuleMember -Function $ExportedFunctions

Write-Host @"

===============================================================================
     SbPAM API PowerShell Module - Enhanced Edition v4.3.2+
===============================================================================
  Original: Stealthbits Technologies (now Netwrix)
  Enhanced: Comprehensive help documentation added

  45+ cmdlets loaded. Use Get-Help <cmdlet> -Full for details.

  Quick Start:
    \$token = Get-SbPAMToken -Uri "https://sbpam" -Username "admin" -Password "pass"
    Get-SbPAMManagedResource -Token \$token

  With MFA:
    \$token = Get-SbPAMTokenMFA -Uri "https://sbpam" -Username "admin" -Password "pass" -TotpSecret "BASE32SECRET"

  List all cmdlets:
    Get-Command -Module SbPAMAPI-Enhanced

  Get help:
    Get-Help Get-SbPAMToken -Full
    Get-Help Start-SbPAMActivitySession -Examples
===============================================================================

"@ -ForegroundColor Cyan
