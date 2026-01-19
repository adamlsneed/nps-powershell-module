# Netwrix Privilege Secure v4.2 API - Complete Reference

**Generated:** 2026-01-18  
**Version:** 25.12.00000  
**Base URL:** `https://<your-nps-server>`  
**Authentication:** Bearer Token (JWT) with MFA

---

## Table of Contents

1. [Authentication](#authentication)
2. [Endpoint Summary](#endpoint-summary)
3. [Detailed Endpoint Reference](#detailed-endpoint-reference)
4. [JSON Schemas](#json-schemas)
5. [PowerShell Examples](#powershell-examples)
6. [cURL Examples](#curl-examples)
7. [Error Handling](#error-handling)

---

## Authentication

### Two-Step Authentication Flow

Netwrix Privilege Secure requires a two-step authentication process:

1. **Initial Sign-in** - Submit credentials to receive a pre-MFA token
2. **MFA Verification** - Submit TOTP code with pre-MFA token to receive full access token

### Step 1: Initial Sign-in

```http
POST /signinBody
Content-Type: application/json

{
    "Login": "username",
    "Password": "password"
}
```

**Response:** Pre-MFA JWT token (string)

### Step 2: MFA Verification

```http
POST /signin2fa
Authorization: Bearer <pre-mfa-token>
Content-Type: application/json

"123456"
```

**Response:** Full access JWT token (string)

### Using the Token

All subsequent API calls require the Authorization header:

```http
Authorization: Bearer <full-access-token>
Content-Type: application/json
```

---

## Endpoint Summary

### Total Verified Endpoints: 55+

| Category | Endpoints | Records |
|----------|-----------|--------|
| Authentication | 2 | - |
| Managed Resources | 3 | 55 |
| Credentials | 4 | 661 |
| Activities | 2 | 14 |
| Activity Sessions | 3 | 219 |
| Access Control Policies | 2 | 8 |
| Platforms | 2 | 14 |
| Host Scanning | 3 | 110+ |
| Action Management | 8 | 6,500+ |
| Managed Accounts | 4 | 685 |
| System & Config | 12 | - |

---

## Detailed Endpoint Reference

### System & Health

| Endpoint | Method | Response | Description |
|----------|--------|----------|-------------|
| `/api/v1/Version` | GET | String | Returns version (e.g., "25.12.00000") |
| `/api/v1/Health` | GET | String | Returns health status ("Healthy") |
| `/api/v1/LicenseInfo` | GET | Object | License details, credits, expiration |
| `/api/v1/Log` | GET | Array | System log files (151 items) |
| `/api/v1/Email` | GET | Array | Email configurations |

### Managed Resources

| Endpoint | Method | Response | Description |
|----------|--------|----------|-------------|
| `/api/v1/ManagedResource` | GET | Array | All managed resources (55) |
| `/api/v1/ManagedResource/Search` | GET | Paginated | Paginated search |
| `/api/v1/ManagedResource/{id}` | GET | Object | Single resource by ID |
| `/api/v1/ManagedResource/{id}/Group` | GET | Array | Groups for resource |

### Credentials

| Endpoint | Method | Response | Description |
|----------|--------|----------|-------------|
| `/api/v1/Credential` | GET | Array | All credentials (limited) |
| `/api/v1/Credential/Search` | GET | Paginated | Paginated search (661) |
| `/api/v1/Credential/{id}` | GET | Object | Single credential by ID |
| `/api/v1/Credential/Count` | GET | Integer | Total credential count |

### Activities

| Endpoint | Method | Response | Description |
|----------|--------|----------|-------------|
| `/api/v1/Activity` | GET | Array | All activities (14) |
| `/api/v1/Activity/{id}` | GET | Object | Single activity by ID |
| `/api/v1/ActivityGroup` | GET | Array | Activity groups (2) |

### Activity Sessions

| Endpoint | Method | Response | Description |
|----------|--------|----------|-------------|
| `/api/v1/ActivitySession` | GET | Array | All sessions (219) |
| `/api/v1/ActivitySession/Search` | GET | Paginated | Paginated search |
| `/api/v1/ActivitySession/{id}` | GET | Object | Single session by ID |
| `/api/v1/ActivitySession/{id}/Log` | GET | Object | Session logs |

### Access Control Policies

| Endpoint | Method | Response | Description |
|----------|--------|----------|-------------|
| `/api/v1/AccessControlPolicy` | GET | Array | All policies (8) |
| `/api/v1/AccessControlPolicy/{id}` | GET | Object | Single policy by ID |
| `/api/v1/ProtectionPolicy` | GET | Array | Protection policies |
| `/api/v1/ProtectionPolicy/Search` | GET | Paginated | Paginated search |
| `/api/v1/ScheduledChangePolicy` | GET | Array | Scheduled change policies (5) |

### Platforms

| Endpoint | Method | Response | Description |
|----------|--------|----------|-------------|
| `/api/v1/Platform` | GET | Array | All platforms (14) |
| `/api/v1/Platform/{id}` | GET | Object | Single platform by ID |

### Host Scanning

| Endpoint | Method | Response | Description |
|----------|--------|----------|-------------|
| `/api/v1/HostScanJob/Host` | GET | Array | Scanned hosts (39) |
| `/api/v1/HostScanJob/User` | GET | Array | Scanned users (71) |
| `/api/v1/HostScanJob/{id}` | GET | Object | Single scan job by ID |
| `/api/v1/Host` | POST | Object | Host schema/template |
| `/api/v1/User` | POST | Object | User schema/template |

### Action Management

| Endpoint | Method | Response | Description |
|----------|--------|----------|-------------|
| `/api/v1/ActionJob` | GET | Array | All action jobs (1880) |
| `/api/v1/ActionJob/Search` | GET | Paginated | Paginated search |
| `/api/v1/ActionGroup` | GET | Array | Action groups (82) |
| `/api/v1/ActionGroup/{id}` | GET | Object | Single group by ID |
| `/api/v1/ActionGroup/{id}/Action` | GET | Array | Actions in group |
| `/api/v1/ActionQueue` | GET | Array | Action queues (4483) |
| `/api/v1/ActionQueue/Search` | GET | Paginated | Paginated search |
| `/api/v1/ActionQueue/{id}` | GET | Object | Single queue by ID |
| `/api/v1/ActionQueue/{id}/Job` | GET | Object | Queue job details |
| `/api/v1/ActionQueue/{id}/Log` | GET | Object | Queue logs |
| `/api/v1/ActionTemplate` | GET | Array | Action templates (71) |
| `/api/v1/ActionService` | GET | Array | Action services (3) |

### Managed Accounts

| Endpoint | Method | Response | Description |
|----------|--------|----------|-------------|
| `/api/v1/ManagedAccount/Search` | GET | Paginated | Managed accounts (6) |
| `/api/v1/ManagedAccount/HostUser/Search` | GET | Paginated | Host users (679) |
| `/api/v1/ManagedAccountGroup` | GET | Array | Account groups |

### Workflows & Profiles

| Endpoint | Method | Response | Description |
|----------|--------|----------|-------------|
| `/api/v1/ApprovalWorkflow` | GET | Array | Approval workflows (3) |
| `/api/v1/ConnectionProfile` | GET | Array | Connection profiles (1) |

### Service & Configuration

| Endpoint | Method | Response | Description |
|----------|--------|----------|-------------|
| `/api/v1/ServiceRegistration` | GET | Array | Service registrations (18) |
| `/api/v1/Website` | GET | Array | Managed websites (1) |
| `/api/v1/SecretVault` | GET | Array | Secret vaults (2) |

---

## JSON Schemas

### ManagedResource Schema

```json
{
  "id": "guid",
  "name": "string",
  "displayName": "string",
  "platformId": "guid",
  "hostId": "guid",
  "domainConfigId": "guid",
  "type": "integer",
  "serviceAccountId": "guid",
  "websiteId": "guid",
  "azureAdTenantId": "guid",
  "secretVaultId": "guid",
  "nodeId": "guid",
  "createdDateTimeUtc": "datetime",
  "modifiedDateTimeUtc": "datetime"
}
```

### Credential Schema

```json
{
  "id": "guid",
  "name": "string",
  "displayName": "string",
  "domain": "string",
  "userName": "string",
  "type": "integer",
  "managedResourceId": "guid",
  "platformId": "guid",
  "lastVerificationDateTimeUtc": "datetime",
  "lastChangeDateTimeUtc": "datetime",
  "nextChangeDateTimeUtc": "datetime",
  "isDeleted": "boolean",
  "nodeId": "guid",
  "createdDateTimeUtc": "datetime",
  "modifiedDateTimeUtc": "datetime"
}
```

### ActivitySession Schema

```json
{
  "id": "guid",
  "status": "integer",
  "startDateTimeUtc": "datetime",
  "endDateTimeUtc": "datetime",
  "userId": "guid",
  "managedAccountId": "guid",
  "activityId": "guid",
  "credentialId": "guid",
  "managedResourceId": "guid",
  "loginDateTimeUtc": "datetime",
  "logoutDateTimeUtc": "datetime",
  "nodeId": "guid",
  "createdDateTimeUtc": "datetime",
  "modifiedDateTimeUtc": "datetime"
}
```

### ActionJob Schema

```json
{
  "id": "guid",
  "name": "string",
  "type": "integer",
  "disabled": "boolean",
  "isRecurring": "boolean",
  "startDateTimeUtc": "datetime",
  "nextStartTimeUtc": "datetime",
  "recurrenceType": "integer",
  "recurrenceInterval": "integer",
  "recurrenceCount": "integer",
  "hour": "integer",
  "minute": "integer",
  "dayOfWeek": "integer",
  "dayOfMonth": "integer",
  "actionGroupId": "guid",
  "actionQueueId": "guid",
  "hostId": "guid",
  "userId": "guid",
  "managedResourceId": "guid",
  "platformId": "guid",
  "nodeId": "guid",
  "createdDateTimeUtc": "datetime",
  "modifiedDateTimeUtc": "datetime"
}
```

### ActionQueue Schema

```json
{
  "id": "guid",
  "status": "integer",
  "statusDescription": "string",
  "startTime": "datetime",
  "actionQueueActionStatus": "array"
}
```

### ActionTemplate Schema

```json
{
  "id": "guid",
  "displayName": "string",
  "description": "string",
  "newActionDisplayName": "string",
  "icon": "string",
  "definition": "string",
  "userDefined": "boolean",
  "classification": "integer",
  "actionPackId": "guid",
  "pairedActionTemplateId": "guid",
  "actionTemplateParameter": "array",
  "actionTemplateDemand": "array",
  "createdBy": "guid",
  "lastModifiedBy": "guid",
  "nodeId": "guid",
  "createdDateTimeUtc": "datetime",
  "modifiedDateTimeUtc": "datetime"
}
```

### Host Schema

```json
{
  "id": "guid",
  "name": "string",
  "dnsHostName": "string",
  "ipAddress": "string",
  "os": "string",
  "version": "string",
  "distinguishedName": "string",
  "netBiosName": "string",
  "samaccountname": "string",
  "isDomainController": "boolean",
  "isGlobalCatalog": "boolean",
  "isVirtual": "boolean",
  "hasSSH": "boolean",
  "credentialId": "guid",
  "activeDirectoryDomainId": "guid",
  "activeDirectoryObjectId": "guid",
  "objectSid": "string",
  "usnChanged": "integer",
  "users": "array",
  "groups": "array",
  "features": "array",
  "services": "array",
  "scheduledTasks": "array",
  "databases": "array",
  "nodeId": "guid",
  "createdDateTimeUtc": "datetime",
  "modifiedDateTimeUtc": "datetime"
}
```

### User Schema

```json
{
  "id": "guid",
  "name": "string",
  "displayName": "string",
  "firstName": "string",
  "lastName": "string",
  "email": "string",
  "title": "string",
  "department": "string",
  "samaccountname": "string",
  "userPrincipalName": "string",
  "distinguishedName": "string",
  "sid": "string",
  "enabled": "boolean",
  "managed": "boolean",
  "privilege": "integer",
  "unixId": "integer",
  "unixGroupId": "integer",
  "homeDirectory": "string",
  "shell": "string",
  "hostId": "guid",
  "activeDirectoryDomainId": "guid",
  "activeDirectoryObjectId": "guid",
  "passwordChangedDateTimeUtc": "datetime",
  "passwordExpirationDateTimeUtc": "datetime",
  "lastLogonTimestamp": "datetime",
  "expirationDate": "datetime",
  "forcePasswordReset": "boolean",
  "nodeId": "guid",
  "createdDateTimeUtc": "datetime",
  "modifiedDateTimeUtc": "datetime"
}
```

### LicenseInfo Schema

```json
{
  "credits": "integer",
  "maxCredits": "integer",
  "machineID": "string",
  "isTrial": "boolean",
  "isTrialExpired": "boolean",
  "lastActivationTime": "datetime",
  "lastConsumptionTime": "datetime",
  "trialExpirationDate": "datetime",
  "errorMessage": "string",
  "customerInfo": {
    "companyName": "string",
    "address1": "string",
    "city": "string",
    "stateProvince": "string",
    "country": "string",
    "postalCode": "string",
    "phone": "string",
    "email": "string",
    "fullName": "string"
  },
  "creditInfo": [
    {
      "activationName": "string",
      "expirationDate": "datetime",
      "credits": "integer"
    }
  ]
}
```

### ServiceRegistration Schema

```json
{
  "id": "guid",
  "type": "integer",
  "dnsHostName": "string",
  "credentialId": "guid",
  "serviceName": "string",
  "settingsFilePath": "string",
  "settingsFileContents": "string",
  "createdBy": "guid",
  "actionQueueId": "guid",
  "nodeId": "guid",
  "createdDateTimeUtc": "datetime",
  "modifiedDateTimeUtc": "datetime"
}
```

### Website Schema

```json
{
  "id": "guid",
  "managedResourceId": "guid",
  "name": "string",
  "avatarUrl": "string",
  "platformId": "guid",
  "associatedResourceId": "guid",
  "logonUrl": "string",
  "uris": "array"
}
```

### SecretVault Schema

```json
{
  "id": "guid",
  "managedResourceId": "guid",
  "platformId": "guid",
  "name": "string",
  "description": "string",
  "policyIds": "array"
}
```

### ScheduledChangePolicy Schema

```json
{
  "id": "guid",
  "name": "string",
  "description": "string",
  "frequency": "integer",
  "periodValue": "integer",
  "daysOfWeek": "string",
  "dayNumber": "integer",
  "localTime": "datetime",
  "utcTime": "datetime",
  "nodeId": "guid",
  "createdDateTimeUtc": "datetime",
  "modifiedDateTimeUtc": "datetime"
}
```

---

## PowerShell Examples

See the complete PowerShell module: `NPS_PowerShell_Complete_Reference.ps1`

### Quick Start

```powershell
# Load the module
. .\NPS_PowerShell_Complete_Reference.ps1

# Connect to NPS
Connect-NPSServer -Server "https://your-nps-server" `
    -Username "admin" `
    -Password "YourPassword" `
    -MfaCode "123456"

# Get system health
Get-NPSHealth
Get-NPSVersion

# List resources
Get-NPSManagedResource
Get-NPSCredential -Search
Get-NPSActivitySession -Search

# Get specific items
Get-NPSManagedResource -Id "resource-guid"
Get-NPSCredential -Id "credential-guid"

# Get counts
Get-NPSCredential -Count

# Run health check
Test-NPSServices
```

---

## cURL Examples

### Authentication

```bash
# Step 1: Initial sign-in
PRE_TOKEN=$(curl -sk -X POST "https://your-nps-server/signinBody" \
  -H "Content-Type: application/json" \
  -d '{"Login":"admin","Password":"YourPassword"}' | tr -d '"' )

# Step 2: MFA verification
TOKEN=$(curl -sk -X POST "https://your-nps-server/signin2fa" \
  -H "Authorization: Bearer $PRE_TOKEN" \
  -H "Content-Type: application/json" \
  -d '"123456"' | tr -d '"' )

echo "Token: $TOKEN"
```

### API Calls

```bash
# Get version
curl -sk "https://your-nps-server/api/v1/Version" \
  -H "Authorization: Bearer $TOKEN"

# Get health
curl -sk "https://your-nps-server/api/v1/Health" \
  -H "Authorization: Bearer $TOKEN"

# Get managed resources
curl -sk "https://your-nps-server/api/v1/ManagedResource" \
  -H "Authorization: Bearer $TOKEN" | jq '.'

# Get credentials (paginated)
curl -sk "https://your-nps-server/api/v1/Credential/Search" \
  -H "Authorization: Bearer $TOKEN" | jq '.'

# Get credential count
curl -sk "https://your-nps-server/api/v1/Credential/Count" \
  -H "Authorization: Bearer $TOKEN"

# Get activity sessions
curl -sk "https://your-nps-server/api/v1/ActivitySession/Search" \
  -H "Authorization: Bearer $TOKEN" | jq '.'

# Get specific resource by ID
curl -sk "https://your-nps-server/api/v1/ManagedResource/{id}" \
  -H "Authorization: Bearer $TOKEN" | jq '.'
```

---

## Error Handling

### Common HTTP Status Codes

| Code | Meaning | Action |
|------|---------|--------|
| 200 | Success | Process response |
| 400 | Bad Request | Check request body/parameters |
| 401 | Unauthorized | Re-authenticate |
| 403 | Forbidden | Check permissions/MFA |
| 404 | Not Found | Check endpoint/ID |
| 405 | Method Not Allowed | Use correct HTTP method |
| 500 | Server Error | Contact administrator |

### Authentication Errors

- **403 after signin**: MFA not completed - call `/signin2fa`
- **401 on API call**: Token expired - re-authenticate
- **Invalid MFA code**: Verify TOTP code is current

---

## Notes

1. **MFA Required**: All API access requires completing MFA authentication
2. **Token Expiration**: JWT tokens expire; implement refresh logic
3. **Pagination**: Search endpoints return paginated results with `recordsTotal`
4. **Rate Limits**: Not documented; implement exponential backoff
5. **SSL/TLS**: Production should use valid certificates

---

*Documentation generated from live API discovery on Netwrix Privilege Secure v25.12.00000*
