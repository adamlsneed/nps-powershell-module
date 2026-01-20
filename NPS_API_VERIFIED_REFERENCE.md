# Netwrix Privilege Secure (NPS) API Reference
## Verified Endpoints - January 2026

This documentation is based on live testing against NPS v25.12.00000.

---

## Authentication

### Two-Step MFA Authentication Flow

**Step 1: Initial Login**
```http
POST /signinBody
Content-Type: application/json

{
    "Login": "username",
    "Password": "password"
}

Response: "<pre-mfa-token>"
```

**Step 2: MFA Verification**
```http
POST /signin2fa
Authorization: Bearer <pre-mfa-token>
Content-Type: application/json

"123456"

Response: "<full-access-jwt-token>"
```

> **Important Notes:**
> - MFA code is sent as a plain JSON string, not an object
> - Use field names `Login` and `Password` (not `userName`/`password`)
> - Tokens expire after approximately 15 minutes

---

## Endpoint Reference

### Legend
| Symbol | Meaning |
|--------|--------|
| ✅ | Endpoint works with this method |
| ❌ | Method not supported or returns error |
| 🔸 | Requires request body (even if empty `{}`) |
| 📄 | Returns paginated results |

---

## System Endpoints

| Endpoint | GET | POST | Records | Notes |
|----------|-----|------|---------|-------|
| `/api/v1/Health` | ✅ | ✅ | - | Returns "Healthy" |
| `/api/v1/Version` | ✅ | ❌ | - | Returns version string (e.g., "25.12.00000") |
| `/api/v1/LicenseInfo` | ✅ | ❌ | - | License details |

---

## Managed Resources

| Endpoint | GET | POST | Records | Notes |
|----------|-----|------|---------|-------|
| `/api/v1/ManagedResource` | ✅ | ✅🔸 | 57 | List/Create resources |
| `/api/v1/ManagedResource/{id}` | ✅ | - | - | Get by ID, supports PUT/DELETE |
| `/api/v1/ManagedResource/Search` | ✅📄 | ❌ | 58 | Paginated search |

---

## Credentials

| Endpoint | GET | POST | Records | Notes |
|----------|-----|------|---------|-------|
| `/api/v1/Credential` | ✅ | ❌ | 6 | List credentials |
| `/api/v1/Credential/{id}` | ✅ | - | - | Get by ID, supports PUT/DELETE |
| `/api/v1/Credential/Search` | ✅📄 | ❌ | 10 | Paginated search |
| `/api/v1/Credential/Count` | ✅ | ❌ | - | Returns integer count |

---

## Activities

| Endpoint | GET | POST | Records | Notes |
|----------|-----|------|---------|-------|
| `/api/v1/Activity` | ✅ | ❌ | 14 | List activities |
| `/api/v1/Activity/{id}` | ✅ | - | - | Get by ID, supports PUT/DELETE |
| `/api/v1/Activity/Search` | ❌ | ❌ | - | **Does not exist** |

---

## Activity Sessions

| Endpoint | GET | POST | Records | Notes |
|----------|-----|------|---------|-------|
| `/api/v1/ActivitySession` | ✅ | ❌ | 219 | List sessions |
| `/api/v1/ActivitySession/{id}` | ✅ | - | - | Get by ID |
| `/api/v1/ActivitySession/Search` | ✅📄 | ❌ | 10 | Paginated search |
| `/api/v1/ActivitySession/{id}/Log` | ✅ | - | - | Session logs (sub-resource) |

---

## Access Control Policies

| Endpoint | GET | POST | Records | Notes |
|----------|-----|------|---------|-------|
| `/api/v1/AccessControlPolicy` | ✅ | ❌ | 8 | List policies |
| `/api/v1/AccessControlPolicy/{id}` | ✅ | - | - | Get by ID, supports PUT/DELETE |
| `/api/v1/AccessControlPolicy/Search` | ❌ | ❌ | - | **Does not exist** |

---

## Host (POST-Only for List)

| Endpoint | GET | POST | Records | Notes |
|----------|-----|------|---------|-------|
| `/api/v1/Host` | ❌ | ✅🔸 | - | **Requires POST with body** |
| `/api/v1/Host/{id}` | ✅ | - | - | Get by ID, supports PUT/DELETE |

> **Important:** The `/api/v1/Host` endpoint only accepts POST requests with a body (can be empty `{}`).

---

## Host Scan Jobs

| Endpoint | GET | POST | Records | Notes |
|----------|-----|------|---------|-------|
| `/api/v1/HostScanJob` | ✅ | ❌ | 2,134 | List all scan jobs |
| `/api/v1/HostScanJob/Host` | ✅ | ❌ | 39 | Host-type scans |
| `/api/v1/HostScanJob/User` | ✅ | ❌ | 71 | User-type scans |
| `/api/v1/HostScanJob/Search` | ❌ | ❌ | - | **Does not exist** |

---

## Action Management

| Endpoint | GET | POST | Records | Notes |
|----------|-----|------|---------|-------|
| `/api/v1/ActionGroup` | ✅ | ✅ | 92 | List/Create groups |
| `/api/v1/ActionGroup/{id}` | ✅ | - | - | Get by ID, supports PUT/DELETE |
| `/api/v1/ActionJob` | ✅ | ❌ | 1,880 | List jobs |
| `/api/v1/ActionJob/Search` | ✅📄 | ❌ | 25 | Paginated search |
| `/api/v1/ActionQueue` | ✅ | ❌ | 4,483 | List queue items |
| `/api/v1/ActionQueue/Search` | ✅📄 | ❌ | 100 | Paginated search |
| `/api/v1/ActionTemplate` | ✅ | ❌ | 71 | List templates |
| `/api/v1/ActionService` | ✅ | ❌ | 3 | List services |

---

## Platform

| Endpoint | GET | POST | Records | Notes |
|----------|-----|------|---------|-------|
| `/api/v1/Platform` | ✅ | ❌ | 14 | List platforms |
| `/api/v1/Platform/{id}` | ✅ | - | - | Get by ID, supports PUT |
| `/api/v1/Platform/Search` | ❌ | ❌ | - | Returns 400 |

---

## Users (POST-Only for List)

| Endpoint | GET | POST | Records | Notes |
|----------|-----|------|---------|-------|
| `/api/v1/User` | ❌ | ✅🔸 | - | **Requires POST with body** |
| `/api/v1/User/{id}` | ✅ | - | - | Get by ID, supports PUT/DELETE |
| `/api/v1/User/Search` | ❌ | ❌ | - | Returns 400 |

---

## Managed Accounts

| Endpoint | GET | POST | Records | Notes |
|----------|-----|------|---------|-------|
| `/api/v1/ManagedAccount` | ❌ | ❌ | - | Returns 400 - use Search |
| `/api/v1/ManagedAccount/Search` | ✅📄 | ❌ | 6 | Use this for listing |
| `/api/v1/ManagedAccount/HostUser/Search` | ✅📄 | ❌ | - | Host user accounts |

---

## Logs

| Endpoint | GET | POST | Records | Notes |
|----------|-----|------|---------|-------|
| `/api/v1/Log` | ✅ | ❌ | 151 | List logs |

---

## Configuration & Policies

| Endpoint | GET | POST | Records | Notes |
|----------|-----|------|---------|-------|
| `/api/v1/ServiceRegistration` | ✅ | ❌ | 18 | Service registrations |
| `/api/v1/Website` | ✅ | ❌ | 1 | Website configuration |
| `/api/v1/SecretVault` | ✅ | ❌ | 2 | Secret vault entries |
| `/api/v1/ApprovalWorkflow` | ✅ | ❌ | 3 | Approval workflows |
| `/api/v1/ScheduledChangePolicy` | ✅ | ❌ | 5 | Scheduled change policies |
| `/api/v1/ProtectionPolicy` | ✅ | ❌ | 0 | Protection policies |
| `/api/v1/ActivityGroup` | ✅ | ❌ | 2 | Activity groups |
| `/api/v1/ConnectionProfile` | ✅ | ❌ | 1 | Connection profiles |

---

## Groups (Limited Support)

| Endpoint | GET | POST | Records | Notes |
|----------|-----|------|---------|-------|
| `/api/v1/Group` | ❌ | ❌ | - | Returns 405/500 |
| `/api/v1/Group/Search` | ❌ | ❌ | - | Returns 400 |

---

## Non-Existent Endpoints (404)

The following endpoints do not exist in NPS v25.12:

- `/api/v1/NpsUser`
- `/api/v1/Registration`
- `/api/v1/Configuration`
- `/api/v1/Session`
- `/api/v1/Audit`
- `/api/v1/Service`
- `/api/v1/ScheduledTask`
- `/api/v1/Role`
- `/api/v1/Settings`
- `/api/v1/Vault`
- `/api/v1/Domain`

---

## Data Volumes (Demo Instance)

| Resource | Record Count |
|----------|-------------|
| ManagedResource | 57 |
| Credential | 6-10 |
| Activity | 14 |
| ActivitySession | 219 |
| AccessControlPolicy | 8 |
| HostScanJob | 2,134 |
| ActionGroup | 92 |
| ActionJob | 1,880 |
| ActionQueue | 4,483 |
| ActionTemplate | 71 |
| Platform | 14 |
| ManagedAccount | 6 |
| Log | 151 |
| ServiceRegistration | 18 |
| ApprovalWorkflow | 3 |
| ScheduledChangePolicy | 5 |
| ActivityGroup | 2 |
| SecretVault | 2 |
| Website | 1 |
| ConnectionProfile | 1 |

---

## Common Response Patterns

### List Response (Array)
```json
[
    { "id": "guid", "name": "...", ... },
    { "id": "guid", "name": "...", ... }
]
```

### Search Response (Paginated)
```json
{
    "draw": 0,
    "recordsTotal": 100,
    "recordsFiltered": 100,
    "data": [ ... ]
}
```

### Single Resource Response
```json
{
    "id": "guid",
    "name": "Resource Name",
    "description": "...",
    ...
}
```

### Scalar Response
```
42
```
(For endpoints like `/api/v1/Credential/Count`)

---

## Error Responses

| Status | Meaning |
|--------|--------|
| 200 | Success |
| 201 | Created (POST) |
| 400 | Bad Request - check body/parameters |
| 401 | Unauthorized - token expired or invalid |
| 403 | Forbidden - insufficient permissions |
| 404 | Not Found - endpoint doesn't exist |
| 405 | Method Not Allowed - try different HTTP method |
| 500 | Server Error |

---

## PowerShell Module Functions

The NPS-Module-Complete.psm1 provides 67 cmdlets for all verified endpoints:

### Authentication
- `Connect-NPSServer` - Authenticate with MFA
- `Disconnect-NPSServer` - Clear session
- `Test-NPSConnection` - Verify connection

### Core Resources
- `Get-NPSManagedResource` - Managed resources
- `Get-NPSCredential` - Credentials
- `Get-NPSActivity` - Activities
- `Get-NPSActivitySession` - Activity sessions
- `Get-NPSAccessControlPolicy` - Access policies
- `Get-NPSHost` - Hosts (POST-only)
- `Get-NPSUser` - Users (POST-only)
- `Get-NPSManagedAccount` - Managed accounts

### Actions & Jobs
- `Get-NPSActionGroup` - Action groups
- `Get-NPSActionJob` - Action jobs
- `Get-NPSActionQueue` - Action queue
- `Get-NPSActionTemplate` - Action templates
- `Get-NPSActionService` - Action services

### Configuration
- `Get-NPSPlatform` - Platforms
- `Get-NPSHostScanJob` - Host scan jobs
- `Get-NPSServiceRegistration` - Service registrations
- `Get-NPSApprovalWorkflow` - Approval workflows
- `Get-NPSScheduledChangePolicy` - Scheduled policies
- `Get-NPSProtectionPolicy` - Protection policies
- `Get-NPSActivityGroup` - Activity groups
- `Get-NPSConnectionProfile` - Connection profiles
- `Get-NPSSecretVault` - Secret vaults
- `Get-NPSWebsite` - Website config

### System
- `Get-NPSHealth` - Health status
- `Get-NPSVersion` - Version info
- `Get-NPSLicenseInfo` - License info
- `Get-NPSLog` - Logs

---

*Generated: January 20, 2026 | NPS Version: 25.12.00000*
*Tested against demo instance with 10,000+ records*
