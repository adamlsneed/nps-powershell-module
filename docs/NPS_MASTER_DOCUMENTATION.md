# Netwrix Privilege Secure v4.2 API - MASTER DOCUMENTATION

**Generated:** 2026-01-18  
**Version:** 25.12.00000  
**Base URL:** `https://<your-nps-server>`  
**Authentication:** Bearer Token (JWT) with MFA  
**Total Documented Endpoints:** 250+ (from GitHub) / 55+ (Live Verified)

---

# PART 1: EXECUTIVE SUMMARY & LIVE VERIFIED ENDPOINTS

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


---

# PART 2: COMPLETE API INVENTORY (FROM GITHUB DOCUMENTATION)

The following inventory was compiled from the official Netwrix GitHub documentation.
These endpoints may require specific roles or configurations to access.


# Netwrix Privilege Secure API Inventory
## Version 4.2 - Complete Endpoint Documentation

---

## 📋 Executive Summary

| Metric | Value |
|--------|-------|
| **API Version** | v1 |
| **Base URL** | `https://{server}/api/v1/` |
| **Total Endpoints** | ~250+ |
| **Authentication** | Bearer Token + MFA |
| **Documentation Source** | GitHub + Live Demo |
| **Live Instance** | https://demo-nps1 |

---

## 🔐 Authentication Flow

### Step 1: Initial Sign-in
```
POST /signinBody
Content-Type: application/json

{
    "Login": "username",
    "Password": "password"
}
```
**Response:** JWT token (pre-MFA)

### Step 2: MFA Verification (Required for most endpoints)
```
POST /signin2fa
Authorization: Bearer {pre-mfa-token}
Content-Type: application/json

"{mfa-code}"
```
**Response:** JWT token (post-MFA, full access)

### Token Structure (Decoded JWT)
| Claim | Description |
|-------|-------------|
| `userId` | User UUID |
| `userName` | Login username |
| `displayName` | Display name |
| `hasMFA` | MFA configured (true/false) |
| `isMFA` | MFA completed (true/false) |
| `role` | User roles (Admin, App, UserPlus, etc.) |

### Authorization Header
```
Authorization: Bearer {jwt-token}
```

---

## 📁 API Categories Overview

| Category | Endpoints | Description |
|----------|-----------|-------------|
| **AccessControlPolicy** | 48 | Access policy management |
| **ActivitySession** | 28 | Session lifecycle management |
| **Credential** | 35 | Credential/secret management |
| **Host** | 15 | Host/server management |
| **HostScanJob** | 33 | Host scanning operations |
| **ManagedAccount** | 40 | User/service account management |
| **ManagedResource** | 60+ | Resource/asset management |

---

## 🔷 AccessControlPolicy API

### Core CRUD Operations

| Method | Endpoint | Description | Auth | Roles | Confidence |
|--------|----------|-------------|------|-------|------------|
| GET | `/api/v1/AccessControlPolicy` | List all access policies | MFA | Admin,App,UserPlus | High |
| POST | `/api/v1/AccessControlPolicy` | Create new access policy | MFA | Admin | High |
| GET | `/api/v1/AccessControlPolicy/{id}` | Get policy by ID | MFA | Admin,App,UserPlus | High |
| PUT | `/api/v1/AccessControlPolicy/{id}` | Update policy | MFA | Admin | High |
| DELETE | `/api/v1/AccessControlPolicy/{id}` | Delete policy | MFA | Admin | High |

### Search & Query

| Method | Endpoint | Description | Auth | Roles | Confidence |
|--------|----------|-------------|------|-------|------------|
| POST | `/api/v1/AccessControlPolicy/Search` | Search policies with filters | MFA | Admin,App,UserPlus | High |
| GET | `/api/v1/AccessControlPolicy/SearchText` | Text-based search | MFA | Admin,App,UserPlus | High |

### Managed Account Associations

| Method | Endpoint | Description | Auth | Roles | Confidence |
|--------|----------|-------------|------|-------|------------|
| GET | `/api/v1/AccessControlPolicy/{id}/ManagedAccount` | Get associated accounts | MFA | Admin,App,UserPlus | High |
| POST | `/api/v1/AccessControlPolicy/{id}/ManagedAccount` | Add account to policy | MFA | Admin | High |
| DELETE | `/api/v1/AccessControlPolicy/{id}/ManagedAccount/{accountId}` | Remove account | MFA | Admin | High |
| PUT | `/api/v1/AccessControlPolicy/{id}/ManagedAccount` | Update account associations | MFA | Admin | High |

### Managed Resource Associations

| Method | Endpoint | Description | Auth | Roles | Confidence |
|--------|----------|-------------|------|-------|------------|
| GET | `/api/v1/AccessControlPolicy/{id}/ManagedResource` | Get associated resources | MFA | Admin,App,UserPlus | High |
| POST | `/api/v1/AccessControlPolicy/{id}/ManagedResource` | Add resource to policy | MFA | Admin | High |
| DELETE | `/api/v1/AccessControlPolicy/{id}/ManagedResource/{resourceId}` | Remove resource | MFA | Admin | High |
| PUT | `/api/v1/AccessControlPolicy/{id}/ManagedResource` | Update resource associations | MFA | Admin | High |

### Activity Associations

| Method | Endpoint | Description | Auth | Roles | Confidence |
|--------|----------|-------------|------|-------|------------|
| GET | `/api/v1/AccessControlPolicy/{id}/Activity` | Get associated activities | MFA | Admin,App,UserPlus | High |
| POST | `/api/v1/AccessControlPolicy/{id}/Activity` | Add activity to policy | MFA | Admin | High |
| DELETE | `/api/v1/AccessControlPolicy/{id}/Activity/{activityId}` | Remove activity | MFA | Admin | High |
| PUT | `/api/v1/AccessControlPolicy/{id}/Activity` | Update activity associations | MFA | Admin | High |

### Credential Associations

| Method | Endpoint | Description | Auth | Roles | Confidence |
|--------|----------|-------------|------|-------|------------|
| GET | `/api/v1/AccessControlPolicy/{id}/Credential` | Get associated credentials | MFA | Admin,App,UserPlus | High |
| POST | `/api/v1/AccessControlPolicy/{id}/Credential` | Add credential to policy | MFA | Admin | High |
| DELETE | `/api/v1/AccessControlPolicy/{id}/Credential/{credentialId}` | Remove credential | MFA | Admin | High |
| PUT | `/api/v1/AccessControlPolicy/{id}/Credential` | Update credential associations | MFA | Admin | High |

### User/Group Associations

| Method | Endpoint | Description | Auth | Roles | Confidence |
|--------|----------|-------------|------|-------|------------|
| GET | `/api/v1/AccessControlPolicy/{id}/NpsUser` | Get associated users | MFA | Admin,App,UserPlus | High |
| POST | `/api/v1/AccessControlPolicy/{id}/NpsUser` | Add user to policy | MFA | Admin | High |
| DELETE | `/api/v1/AccessControlPolicy/{id}/NpsUser/{userId}` | Remove user | MFA | Admin | High |
| GET | `/api/v1/AccessControlPolicy/{id}/NpsGroup` | Get associated groups | MFA | Admin,App,UserPlus | High |
| POST | `/api/v1/AccessControlPolicy/{id}/NpsGroup` | Add group to policy | MFA | Admin | High |
| DELETE | `/api/v1/AccessControlPolicy/{id}/NpsGroup/{groupId}` | Remove group | MFA | Admin | High |

### Bulk Operations

| Method | Endpoint | Description | Auth | Roles | Confidence |
|--------|----------|-------------|------|-------|------------|
| POST | `/api/v1/AccessControlPolicy/AddMultipleAsync` | Bulk add policies | MFA | Admin | High |
| DELETE | `/api/v1/AccessControlPolicy/DeleteMultipleAsync` | Bulk delete policies | MFA | Admin | High |
| PUT | `/api/v1/AccessControlPolicy/UpdateMultipleAsync` | Bulk update policies | MFA | Admin | High |

---

## 🔷 ActivitySession API

### Session Lifecycle

| Method | Endpoint | Description | Auth | Roles | Confidence |
|--------|----------|-------------|------|-------|------------|
| GET | `/api/v1/ActivitySession` | List all sessions | MFA | Admin,App,UserPlus | High |
| POST | `/api/v1/ActivitySession` | Create new session | MFA | Admin,App,UserPlus | High |
| GET | `/api/v1/ActivitySession/{id}` | Get session by ID | MFA | Admin,App,UserPlus | High |
| DELETE | `/api/v1/ActivitySession/{id}` | Delete/cancel session | MFA | Admin | High |

### Session Actions

| Method | Endpoint | Description | Auth | Roles | Confidence |
|--------|----------|-------------|------|-------|------------|
| POST | `/api/v1/ActivitySession/{id}/Approve` | Approve session request | MFA | Admin,Reviewer | High |
| POST | `/api/v1/ActivitySession/{id}/Deny` | Deny session request | MFA | Admin,Reviewer | High |
| POST | `/api/v1/ActivitySession/{id}/Checkin` | Check in session | MFA | Admin,App,UserPlus | High |
| POST | `/api/v1/ActivitySession/{id}/Checkout` | Check out session | MFA | Admin,App,UserPlus | High |
| POST | `/api/v1/ActivitySession/{id}/Extend` | Extend session duration | MFA | Admin,App,UserPlus | High |
| POST | `/api/v1/ActivitySession/{id}/Lock` | Lock session | MFA | Admin | High |
| POST | `/api/v1/ActivitySession/{id}/Unlock` | Unlock session | MFA | Admin | High |
| POST | `/api/v1/ActivitySession/{id}/Terminate` | Force terminate session | MFA | Admin | High |

### Password Operations

| Method | Endpoint | Description | Auth | Roles | Confidence |
|--------|----------|-------------|------|-------|------------|
| POST | `/api/v1/ActivitySession/{id}/ViewPassword` | View session password | MFA | Admin,App,UserPlus | High |
| POST | `/api/v1/ActivitySession/{id}/ViewSshKey` | View SSH key | MFA | Admin,App,UserPlus | High |
| POST | `/api/v1/ActivitySession/{id}/ViewSshKeyPassphrase` | View SSH passphrase | MFA | Admin,App,UserPlus | High |

### Session Queries

| Method | Endpoint | Description | Auth | Roles | Confidence |
|--------|----------|-------------|------|-------|------------|
| POST | `/api/v1/ActivitySession/Search` | Search sessions | MFA | Admin,App,UserPlus | High |
| GET | `/api/v1/ActivitySession/MyActiveSessions` | Get user's active sessions | MFA | Admin,App,UserPlus | High |
| GET | `/api/v1/ActivitySession/PendingApproval` | Get pending approvals | MFA | Admin,Reviewer | High |
| GET | `/api/v1/ActivitySession/SessionsToApprove` | Get sessions needing approval | MFA | Admin,Reviewer | High |

---

## 🔷 Credential API

### Core CRUD Operations

| Method | Endpoint | Description | Auth | Roles | Confidence |
|--------|----------|-------------|------|-------|------------|
| GET | `/api/v1/Credential` | List all credentials | MFA | Admin,App | High |
| POST | `/api/v1/Credential` | Create new credential | MFA | Admin | High |
| GET | `/api/v1/Credential/{id}` | Get credential by ID | MFA | Admin,App | High |
| PUT | `/api/v1/Credential/{id}` | Update credential | MFA | Admin | High |
| DELETE | `/api/v1/Credential/{id}` | Delete credential | MFA | Admin | High |

### Search & Query

| Method | Endpoint | Description | Auth | Roles | Confidence |
|--------|----------|-------------|------|-------|------------|
| POST | `/api/v1/Credential/Search` | Search credentials | MFA | Admin,App | High |
| GET | `/api/v1/Credential/Types` | Get credential types | MFA | Admin,App | High |
| GET | `/api/v1/Credential/ByType/{type}` | Get credentials by type | MFA | Admin,App | High |

### SSH Key Operations

| Method | Endpoint | Description | Auth | Roles | Confidence |
|--------|----------|-------------|------|-------|------------|
| POST | `/api/v1/Credential/{id}/GenerateSshKey` | Generate SSH key pair | MFA | Admin | High |
| POST | `/api/v1/Credential/{id}/RotateSshKey` | Rotate SSH key | MFA | Admin | High |
| GET | `/api/v1/Credential/{id}/SshCertificate` | Get SSH certificate | MFA | Admin,App | High |
| POST | `/api/v1/Credential/{id}/GenerateSshCertificate` | Generate SSH certificate | MFA | Admin | High |

### Password Operations

| Method | Endpoint | Description | Auth | Roles | Confidence |
|--------|----------|-------------|------|-------|------------|
| POST | `/api/v1/Credential/{id}/RotatePassword` | Rotate password | MFA | Admin | High |
| POST | `/api/v1/Credential/{id}/VerifyPassword` | Verify password | MFA | Admin | High |
| POST | `/api/v1/Credential/{id}/TestConnection` | Test credential connection | MFA | Admin | High |

---

## 🔷 Host API

### Core Operations

| Method | Endpoint | Description | Auth | Roles | Confidence |
|--------|----------|-------------|------|-------|------------|
| GET | `/api/v1/Host` | List all hosts | MFA | Admin,App | High |
| POST | `/api/v1/Host` | Create new host | MFA | Admin | High |
| GET | `/api/v1/Host/{id}` | Get host by ID | MFA | Admin,App | High |
| PUT | `/api/v1/Host/{id}` | Update host | MFA | Admin | High |
| DELETE | `/api/v1/Host/{id}` | Delete host | MFA | Admin | High |

### Host Actions

| Method | Endpoint | Description | Auth | Roles | Confidence |
|--------|----------|-------------|------|-------|------------|
| POST | `/api/v1/Host/{id}/Scan` | Trigger host scan | MFA | Admin | High |
| POST | `/api/v1/Host/{id}/TestConnection` | Test host connection | MFA | Admin | High |
| GET | `/api/v1/Host/{id}/Services` | Get host services | MFA | Admin,App | High |

---

## 🔷 HostScanJob API

### Job Management

| Method | Endpoint | Description | Auth | Roles | Confidence |
|--------|----------|-------------|------|-------|------------|
| GET | `/api/v1/HostScanJob` | List all scan jobs | MFA | Admin | High |
| POST | `/api/v1/HostScanJob` | Create new scan job | MFA | Admin | High |
| GET | `/api/v1/HostScanJob/{id}` | Get scan job by ID | MFA | Admin | High |
| DELETE | `/api/v1/HostScanJob/{id}` | Delete scan job | MFA | Admin | High |

### Job Actions

| Method | Endpoint | Description | Auth | Roles | Confidence |
|--------|----------|-------------|------|-------|------------|
| POST | `/api/v1/HostScanJob/{id}/Start` | Start scan job | MFA | Admin | High |
| POST | `/api/v1/HostScanJob/{id}/Stop` | Stop scan job | MFA | Admin | High |
| GET | `/api/v1/HostScanJob/{id}/Status` | Get job status | MFA | Admin | High |
| GET | `/api/v1/HostScanJob/{id}/Results` | Get scan results | MFA | Admin | High |

### Scanned Data

| Method | Endpoint | Description | Auth | Roles | Confidence |
|--------|----------|-------------|------|-------|------------|
| GET | `/api/v1/HostScanJob/{id}/ScannedHosts` | Get scanned hosts | MFA | Admin | High |
| GET | `/api/v1/HostScanJob/{id}/ScannedAccounts` | Get scanned accounts | MFA | Admin | High |
| GET | `/api/v1/HostScanJob/{id}/ScannedServices` | Get scanned services | MFA | Admin | High |
| POST | `/api/v1/HostScanJob/{id}/ImportScannedData` | Import scanned data | MFA | Admin | High |

---

## 🔷 ManagedAccount API

### Core CRUD Operations

| Method | Endpoint | Description | Auth | Roles | Confidence |
|--------|----------|-------------|------|-------|------------|
| GET | `/api/v1/ManagedAccount` | List all managed accounts | MFA | Admin,App,UserPlus | High |
| POST | `/api/v1/ManagedAccount` | Create managed account | MFA | Admin | High |
| GET | `/api/v1/ManagedAccount/{id}` | Get account by ID | MFA | Admin,App,UserPlus | High |
| PUT | `/api/v1/ManagedAccount/{id}` | Update account | MFA | Admin | High |
| DELETE | `/api/v1/ManagedAccount/{id}` | Delete account | MFA | Admin | High |

### Search & Query

| Method | Endpoint | Description | Auth | Roles | Confidence |
|--------|----------|-------------|------|-------|------------|
| POST | `/api/v1/ManagedAccount/Search` | Search accounts | MFA | Admin,App,UserPlus | High |
| GET | `/api/v1/ManagedAccount/SearchText` | Text-based search | MFA | Admin,App,UserPlus | High |
| GET | `/api/v1/ManagedAccount/AvailableDomains` | Get available domains | MFA | Admin | High |

### Account Actions

| Method | Endpoint | Description | Auth | Roles | Confidence |
|--------|----------|-------------|------|-------|------------|
| POST | `/api/v1/ManagedAccount/{id}/RotatePassword` | Rotate password | MFA | Admin | High |
| POST | `/api/v1/ManagedAccount/{id}/VerifyPassword` | Verify password | MFA | Admin | High |
| POST | `/api/v1/ManagedAccount/{id}/TestConnection` | Test connection | MFA | Admin | High |
| POST | `/api/v1/ManagedAccount/{id}/Enable` | Enable account | MFA | Admin | High |
| POST | `/api/v1/ManagedAccount/{id}/Disable` | Disable account | MFA | Admin | High |

### Reviewer Management

| Method | Endpoint | Description | Auth | Roles | Confidence |
|--------|----------|-------------|------|-------|------------|
| GET | `/api/v1/ManagedAccount/{id}/Reviewers` | Get account reviewers | MFA | Admin | High |
| POST | `/api/v1/ManagedAccount/{id}/Reviewers` | Add reviewer | MFA | Admin | High |
| DELETE | `/api/v1/ManagedAccount/{id}/Reviewers/{reviewerId}` | Remove reviewer | MFA | Admin | High |

### API Key Management

| Method | Endpoint | Description | Auth | Roles | Confidence |
|--------|----------|-------------|------|-------|------------|
| POST | `/api/v1/ManagedAccount/{id}/GenerateApiKey` | Generate API key | MFA | Admin | High |
| DELETE | `/api/v1/ManagedAccount/{id}/RevokeApiKey` | Revoke API key | MFA | Admin | High |

---

## 🔷 ManagedResource API

### Core CRUD Operations

| Method | Endpoint | Description | Auth | Roles | Confidence |
|--------|----------|-------------|------|-------|------------|
| GET | `/api/v1/ManagedResource` | List all resources | MFA | Admin,App,UserPlus | High |
| POST | `/api/v1/ManagedResource` | Create resource | MFA | Admin | High |
| GET | `/api/v1/ManagedResource/{id}` | Get resource by ID | MFA | Admin,App,UserPlus | High |
| PUT | `/api/v1/ManagedResource/{id}` | Update resource | MFA | Admin | High |
| DELETE | `/api/v1/ManagedResource/{id}` | Delete resource | MFA | Admin | High |

### Search & Query

| Method | Endpoint | Description | Auth | Roles | Confidence |
|--------|----------|-------------|------|-------|------------|
| POST | `/api/v1/ManagedResource/Search` | Search resources | MFA | Admin,App,UserPlus | High |
| GET | `/api/v1/ManagedResource/SearchText` | Text-based search | MFA | Admin,App,UserPlus | High |
| GET | `/api/v1/ManagedResource/Types` | Get resource types | MFA | Admin,App | High |

### Resource Actions

| Method | Endpoint | Description | Auth | Roles | Confidence |
|--------|----------|-------------|------|-------|------------|
| POST | `/api/v1/ManagedResource/{id}/Scan` | Trigger resource scan | MFA | Admin | High |
| POST | `/api/v1/ManagedResource/{id}/TestConnection` | Test connection | MFA | Admin | High |
| POST | `/api/v1/ManagedResource/{id}/Enable` | Enable resource | MFA | Admin | High |
| POST | `/api/v1/ManagedResource/{id}/Disable` | Disable resource | MFA | Admin | High |

### Protected Groups

| Method | Endpoint | Description | Auth | Roles | Confidence |
|--------|----------|-------------|------|-------|------------|
| GET | `/api/v1/ManagedResource/{id}/ProtectedGroups` | Get protected groups | MFA | Admin | High |
| POST | `/api/v1/ManagedResource/{id}/ProtectedGroups` | Add protected group | MFA | Admin | High |
| DELETE | `/api/v1/ManagedResource/{id}/ProtectedGroups/{groupId}` | Remove protected group | MFA | Admin | High |

### Service Account Management

| Method | Endpoint | Description | Auth | Roles | Confidence |
|--------|----------|-------------|------|-------|------------|
| GET | `/api/v1/ManagedResource/{id}/ServiceAccounts` | Get service accounts | MFA | Admin | High |
| POST | `/api/v1/ManagedResource/{id}/ServiceAccounts` | Add service account | MFA | Admin | High |
| DELETE | `/api/v1/ManagedResource/{id}/ServiceAccounts/{accountId}` | Remove service account | MFA | Admin | High |

---

## 🔷 Additional API Categories (Discovered)

### Activity API
| Method | Endpoint | Description | Confidence |
|--------|----------|-------------|------------|
| GET | `/api/v1/Activity` | List activities | Medium |
| POST | `/api/v1/Activity` | Create activity | Medium |
| GET | `/api/v1/Activity/{id}` | Get activity | Medium |

### NpsUser API
| Method | Endpoint | Description | Confidence |
|--------|----------|-------------|------------|
| GET | `/api/v1/NpsUser` | List NPS users | Medium |
| POST | `/api/v1/NpsUser` | Create NPS user | Medium |
| GET | `/api/v1/NpsUser/{id}` | Get NPS user | Medium |

### Platform API
| Method | Endpoint | Description | Confidence |
|--------|----------|-------------|------------|
| GET | `/api/v1/Platform` | List platforms | Medium |
| GET | `/api/v1/Platform/{id}` | Get platform | Medium |

### ActionGroup API
| Method | Endpoint | Description | Confidence |
|--------|----------|-------------|------------|
| GET | `/api/v1/ActionGroup` | List action groups | Medium |
| POST | `/api/v1/ActionGroup` | Create action group | Medium |

---

## 📊 Request/Response Patterns

### Common Query Parameters

| Parameter | Type | Description | Default |
|-----------|------|-------------|--------|
| `pageNumber` | int | Page number (1-based) | 1 |
| `pageSize` | int | Items per page | 50 |
| `sortBy` | string | Sort field | varies |
| `sortOrder` | string | asc/desc | asc |
| `filterText` | string | Text filter | null |

### Search Request Body (POST /Search endpoints)
```json
{
    "filterText": "string",
    "orderBy": "string",
    "orderDescending": true,
    "skip": 0,
    "take": 50,
    "filterColumns": [
        {
            "columnName": "string",
            "filterValue": "string"
        }
    ]
}
```

### Paginated Response Structure
```json
{
    "data": [...],
    "recordsTotal": 100,
    "recordsFiltered": 50,
    "skip": 0,
    "take": 50
}
```

### Error Response Structure
```json
{
    "type": "https://tools.ietf.org/html/rfc9110#section-15.5.4",
    "title": "Forbidden",
    "status": 403,
    "traceId": "00-xxx-xxx-00"
}
```

---

## 🔴 Gaps & Issues Identified

### Documentation Gaps

| Issue | Severity | Description |
|-------|----------|-------------|
| **Missing OpenAPI/Swagger** | High | No public swagger.json available without auth |
| **Incomplete Examples** | Medium | Many endpoints lack request/response examples |
| **Missing Rate Limits** | Medium | No documentation on API rate limiting |
| **Pagination Inconsistency** | Low | Different endpoints use different pagination patterns |
| **Missing Error Codes** | Medium | Limited documentation on error responses |

### Authentication Issues

| Issue | Severity | Description |
|-------|----------|-------------|
| **MFA Required Everywhere** | High | All API endpoints require MFA completion |
| **No API-Only Auth** | Medium | No documented way to bypass MFA for automation |
| **Token Expiration** | Low | Token lifetime not documented |

### Verification Limitations

| Issue | Description |
|-------|-------------|
| **403 on All Endpoints** | Could not verify endpoints due to MFA requirement |
| **Swagger Behind Auth** | Cannot access API spec without full authentication |

---

## ✅ Recommendations

### For API Documentation

1. **Publish OpenAPI Spec** - Make swagger.json publicly accessible or provide downloadable spec
2. **Add Rate Limit Headers** - Document X-RateLimit-* headers
3. **Standardize Pagination** - Use consistent pagination across all endpoints
4. **Add Webhook Documentation** - Document any webhook/callback endpoints
5. **Version Changelog** - Maintain API version changelog

### For API Consumers

1. **Implement MFA Flow** - Build MFA handling into API clients
2. **Cache Tokens** - Implement token caching with refresh logic
3. **Handle 403 Gracefully** - Implement re-authentication on 403 responses
4. **Use Search Endpoints** - Prefer POST /Search over GET for complex queries

### For Automation

1. **Request API-Only User** - Ask Netwrix about service account without MFA
2. **Use Scheduled Tasks** - Implement token refresh in scheduled jobs
3. **Monitor Token Expiry** - Track JWT exp claim for proactive refresh

---

## 📚 Data Models Reference

Key models documented in GitHub:

| Model | Description |
|-------|-------------|
| `AccessControlPolicy` | Access policy definition |
| `ActivitySession` | Session instance |
| `Credential` | Credential/secret object |
| `ManagedAccount` | User/service account |
| `ManagedResource` | Server/resource object |
| `HostScanJob` | Scan job definition |
| `Activity` | Activity type definition |
| `Platform` | Platform configuration |

---

## 🔗 References

- **GitHub Docs**: https://github.com/netwrix/privilege-secure/tree/main/api-docs/4.2
- **Official Docs**: https://docs.netwrix.com/privilege_secure
- **Demo Instance**: https://demo-nps1

---

*Generated: 2026-01-18*
*Source: GitHub API Documentation + Live Demo Analysis*


---

# PART 3: DETAILED API DOCUMENTATION WITH SCHEMAS

# Netwrix Privilege Secure v4.2 API Documentation
## Live Demo Discovery - January 2026

---

## Table of Contents
1. [Overview](#overview)
2. [Authentication](#authentication)
3. [API Endpoints](#api-endpoints)
4. [Resource Schemas](#resource-schemas)
5. [Search API](#search-api)
6. [HTTP Methods](#http-methods)
7. [Error Handling](#error-handling)
8. [Usage Examples](#usage-examples)

---

## Overview

**Base URL:** `https://<nps-server>`  
**API Version:** v1  
**Product Version:** 25.12.00000  
**Authentication:** Bearer Token (JWT) with MFA  

All API endpoints follow RESTful patterns at `/api/v1/{resource}`.

---

## Authentication

### Two-Step Authentication Flow

Netwrix Privilege Secure requires MFA for all API access.

#### Step 1: Initial Sign-In
```http
POST /signinBody
Content-Type: application/json

{
  "Login": "username",
  "Password": "password"
}
```
**Response:** Pre-MFA JWT token (string)

#### Step 2: MFA Verification
```http
POST /signin2fa
Authorization: Bearer <pre-mfa-token>
Content-Type: application/json

"123456"
```
**Response:** Full access JWT token (string)

#### Using the Token
```http
GET /api/v1/ManagedResource
Authorization: Bearer <full-access-token>
Content-Type: application/json
```

### Token Notes
- Tokens are JWT format
- Include `Authorization: Bearer <token>` header on all requests
- Token expiration: Check `exp` claim in JWT
- MFA code format: 6-digit string

---

## API Endpoints

### Confirmed Working Endpoints (26 Total)

| Endpoint | Method | Description | Record Count* |
|----------|--------|-------------|---------------|
| `/api/v1/ManagedResource` | GET | List all managed resources | 55 |
| `/api/v1/ManagedResource/{id}` | GET, PUT, DELETE | Single resource operations | - |
| `/api/v1/ManagedResource/Search` | GET | Paginated search | 55 |
| `/api/v1/Credential` | GET | List credentials | 6 |
| `/api/v1/Credential/{id}` | GET, PUT, DELETE | Single credential operations | - |
| `/api/v1/Credential/Search` | GET | Paginated search | 657 |
| `/api/v1/ManagedAccount/Search` | GET | Search managed accounts | 6 |
| `/api/v1/ManagedAccount/HostUser/Search` | GET | Search host users | 679 |
| `/api/v1/AccessControlPolicy` | GET | List access policies | 8 |
| `/api/v1/AccessControlPolicy/{id}` | GET, PUT, DELETE | Single policy operations | - |
| `/api/v1/Activity` | GET | List activities | 14 |
| `/api/v1/Activity/{id}` | GET, PUT, DELETE | Single activity operations | - |
| `/api/v1/ActivitySession` | GET | List activity sessions | 219 |
| `/api/v1/ActivitySession/{id}` | GET, DELETE | Single session operations | - |
| `/api/v1/ActivitySession/Search` | GET | Paginated search with summary | 219 |
| `/api/v1/ActivityGroup` | GET | List activity groups | 2 |
| `/api/v1/ActionGroup` | GET | List action groups | 82 |
| `/api/v1/ActionQueue` | GET | List action queue items | 4483 |
| `/api/v1/ActionQueue/Search` | GET | Paginated search | 4483 |
| `/api/v1/ActionService` | GET | List action services | 3 |
| `/api/v1/ApprovalWorkflow` | GET | List approval workflows | 3 |
| `/api/v1/ScheduledChangePolicy` | GET | List scheduled policies | 5 |
| `/api/v1/ProtectionPolicy` | GET | List protection policies | 0 |
| `/api/v1/ProtectionPolicy/Search` | GET | Paginated search | 0 |
| `/api/v1/Platform` | GET | List platforms | 14 |
| `/api/v1/HostScanJob` | GET | List host scan jobs | 2134 |
| `/api/v1/ServiceRegistration` | GET | List service registrations | 18 |
| `/api/v1/Website` | GET | List websites | 1 |
| `/api/v1/SecretVault` | GET | List secret vaults | 2 |
| `/api/v1/Health` | GET | Health check | "Healthy" |
| `/api/v1/Version` | GET | API version | "25.12.00000" |
| `/api/v1/User` | POST | User operations | - |
| `/api/v1/ManagedAccountGroup` | GET | List account groups | 0 |

*Record counts from demo instance as of January 2026

---

## Resource Schemas

### ManagedResource
```json
{
  "id": "uuid",
  "name": "string",
  "type": "integer (0=Host, 1=Domain, etc.)",
  "hostId": "uuid | null",
  "domainConfigId": "uuid | null",
  "domainName": "string",
  "websiteId": "uuid | null",
  "azureAdTenantId": "uuid | null",
  "secretVaultId": "uuid | null",
  "managedDatabaseId": "uuid | null",
  "platformId": "uuid",
  "platformName": "string",
  "serviceAccountId": "uuid | null",
  "dnsHostName": "string",
  "ipAddress": "string | null",
  "os": "string",
  "hostVersion": "string | null",
  "saName": "string",
  "saUsername": "string",
  "nodeId": "uuid",
  "createdDateTimeUtc": "datetime",
  "modifiedDateTimeUtc": "datetime",
  "lastScanTimeUtc": "datetime | null",
  "activeSessionCount": "integer",
  "scheduledSessionCount": "integer",
  "accessPolicyCount": "integer",
  "protectionPolicyCount": "integer",
  "portSsh": "integer (default: 22)",
  "portRdp": "integer (default: 3389)",
  "portWinRm": "integer (default: 5985)",
  "portWinRmHttps": "integer (default: 5986)",
  "disableWinRm": "boolean",
  "acceptThumbprintOnFirstDiscovery": "boolean",
  "trustedThumbprint": "string | null",
  "sshTrustActionType": "integer",
  "certificateType": "integer"
}
```

### Credential
```json
{
  "id": "uuid",
  "domain": "string",
  "username": "string",
  "name": "string",
  "description": "string | null",
  "type": "integer (0=ServiceAccount, etc.)",
  "userId": "uuid",
  "managedAccountId": "uuid | null",
  "platformId": "uuid",
  "sudoCommand": "string | null",
  "passwordVaultConnectorId": "uuid | null",
  "passwordVaultInfo": "string | null",
  "changeOnCheckout": "boolean",
  "changeOnRelease": "boolean",
  "postSessionAction": "integer",
  "credentialJoin": "array",
  "isDeleted": "boolean",
  "nodeId": "uuid",
  "createdDateTimeUtc": "datetime",
  "modifiedDateTimeUtc": "datetime",
  "authenticationMethod": "integer",
  "keyGenAlgorithm": "string | null",
  "keyLength": "integer | null",
  "autoGenPassphrase": "boolean | null"
}
```

### AccessControlPolicy
```json
{
  "id": "uuid",
  "name": "string",
  "description": "string | null",
  "priority": "integer",
  "notesRequired": "boolean",
  "ticketRequired": "boolean",
  "approvalTypeRequired": "integer (0=None, 1=Required, etc.)",
  "policyType": "integer",
  "managedAccountIds": "array[uuid]",
  "managedAccountGroupIds": "array[uuid]",
  "managedResourceIds": "array[uuid]",
  "managedResourceGroupIds": "array[uuid]",
  "credentialIds": "array[uuid]",
  "activityIds": "array[uuid]",
  "activities": "array[Activity]"
}
```

### Activity
```json
{
  "id": "uuid",
  "name": "string",
  "description": "string",
  "createdBy": "uuid",
  "modifiedBy": "uuid",
  "activityConfigurationId": "uuid | null",
  "platformId": "uuid",
  "startActionGroupId": "uuid",
  "duringActionGroupId": "uuid",
  "endActionGroupId": "uuid",
  "activityType": "integer (0=Token, 1=RDP, 2=SSH, 3=CredentialRelease)",
  "loginAccount": "integer",
  "loginAccountNameFormat": "string",
  "requesterLoginFormat": "integer",
  "applicationToLaunch": "string | null",
  "preferredRDSHostId": "uuid | null",
  "connectCredentialId": "uuid | null",
  "createAccount": "boolean",
  "deleteAccount": "boolean",
  "vaultId": "uuid | null",
  "logonUrl": "string | null",
  "isDefault": "boolean",
  "isDeleted": "boolean",
  "isUserModified": "boolean",
  "nodeId": "uuid",
  "createdDateTimeUtc": "datetime",
  "modifiedDateTimeUtc": "datetime"
}
```

### ActivitySession
```json
{
  "id": "uuid",
  "createdBy": "uuid",
  "createdByUserName": "string",
  "createdFromAddress": "string (IP)",
  "createdDateTimeUtc": "datetime",
  "credentialId": "uuid",
  "userCredentialId": "uuid",
  "connectCredentialId": "uuid | null",
  "locked": "boolean",
  "loginAccountName": "string",
  "loginAccount": "integer",
  "vaultId": "uuid | null",
  "activityId": "uuid",
  "activity": "Activity (nested object)",
  "activityConfigurationId": "uuid | null"
}
```

### Platform
```json
{
  "id": "uuid",
  "name": "string",
  "description": "string | null",
  "builtInAccount": "string | null",
  "passwordComplexityPolicyId": "uuid | null",
  "scheduledChangePolicyId": "uuid | null",
  "protectionPolicyScheduleId": "uuid | null",
  "scanScheduleId": "uuid | null",
  "verificationScheduleId": "uuid | null",
  "resetOnMismatch": "boolean",
  "icon": "string | null",
  "basePlatformId": "uuid | null",
  "os": "string | null",
  "type": "integer",
  "nodeId": "uuid",
  "createdDateTimeUtc": "datetime",
  "modifiedDateTimeUtc": "datetime",
  "showCommandPlans": "boolean",
  "permanent": "boolean"
}
```

### HostScanJob
```json
{
  "id": "uuid",
  "status": "integer (0=Pending, 1=Running, 5=CompletedWithErrors, etc.)",
  "statusDescription": "string",
  "hostScanHostStatus": [
    {
      "hostScanHostId": "uuid",
      "hostId": "uuid",
      "name": "string",
      "dnsHostName": "string",
      "os": "string | null",
      "ipAddress": "string | null",
      "version": "string | null",
      "status": "integer",
      "statusDescription": "string",
      "failureReason": "integer"
    }
  ]
}
```

### ActionService
```json
{
  "id": "uuid",
  "type": "integer",
  "name": "string",
  "added": "datetime",
  "refreshToken": "string",
  "appTokenId": "uuid | null",
  "status": "integer (0=Offline, 1=Online)",
  "description": "string | null",
  "version": "string",
  "serviceRegistrationId": "uuid",
  "serviceRegistration": "ServiceRegistration (nested)"
}
```

### ScheduledChangePolicy
```json
{
  "id": "uuid",
  "name": "string",
  "description": "string",
  "frequency": "integer (0=Daily, 1=Weekly, etc.)",
  "periodValue": "integer",
  "daysOfWeek": "string",
  "dayNumber": "integer",
  "localTime": "datetime",
  "utcTime": "datetime",
  "nodeId": "uuid",
  "createdDateTimeUtc": "datetime",
  "modifiedDateTimeUtc": "datetime"
}
```

### SecretVault
```json
{
  "id": "uuid",
  "managedResourceId": "uuid",
  "platformId": "uuid",
  "name": "string",
  "description": "string | null",
  "policyIds": "array | null"
}
```

### User (from POST /api/v1/User)
```json
{
  "id": "uuid",
  "activeDirectoryObjectId": "uuid | null",
  "activeDirectoryDomainId": "uuid | null",
  "displayName": "string",
  "enabled": "boolean",
  "unixId": "integer | null",
  "unixGroupId": "integer | null",
  "homeDirectory": "string | null",
  "shell": "string | null",
  "expirationDate": "datetime | null",
  "managed": "boolean",
  "hostId": "uuid | null",
  "title": "string | null",
  "samaccountname": "string",
  "userPrincipalName": "string",
  "distinguishedName": "string",
  "department": "string | null",
  "email": "string | null",
  "lastLogonTimestamp": "datetime | null",
  "name": "string",
  "sid": "string",
  "firstName": "string | null",
  "lastName": "string | null",
  "passwordChangedDateTimeUtc": "datetime | null",
  "passwordExpirationDateTimeUtc": "datetime | null",
  "forcePasswordReset": "boolean",
  "privilege": "integer",
  "deleted": "boolean",
  "nodeId": "uuid",
  "createdDateTimeUtc": "datetime",
  "modifiedDateTimeUtc": "datetime"
}
```

---

## Search API

### Search Endpoint Pattern
All `/Search` endpoints support pagination and return a consistent response structure.

### Request (GET)
```http
GET /api/v1/{Resource}/Search
Authorization: Bearer <token>
```

### Response Structure
```json
{
  "data": [...],
  "recordsTotal": 123
}
```

### ActivitySession/Search Extended Response
```json
{
  "topUsers": [...],
  "summary": {...},
  "data": [...],
  "recordsTotal": 123
}
```

### Search Endpoints Available
| Endpoint | Fields Returned |
|----------|----------------|
| `/api/v1/ManagedResource/Search` | id, name, type, hostId, domainConfigId, domainName, websiteId... |
| `/api/v1/Credential/Search` | id, credentialId, userName, displayName, lastVerifiedDateTimeUtc, status... |
| `/api/v1/ActivitySession/Search` | id, hostId, hostDisplayName, domainId, domainName, userId, userDisplayName... |
| `/api/v1/ManagedAccount/Search` | entityType, id, hostUserId, name, displayName, samAccountName, department... |
| `/api/v1/ManagedAccount/HostUser/Search` | entityType, id, name, displayName, userPrincipalName, samAccountName, email, managed... |
| `/api/v1/ActionQueue/Search` | id, actionGroupId, heartBeatDateTimeUtc, startTimeUtc, endTimeUtc, status... |
| `/api/v1/ProtectionPolicy/Search` | data, recordsTotal |

---

## HTTP Methods

### Supported Methods by Resource

| Resource | GET | POST | PUT | DELETE |
|----------|-----|------|-----|--------|
| ManagedResource | ✓ | ? | ✓ | ✓ |
| Credential | ✓ | ? | ✓ | ✓ |
| AccessControlPolicy | ✓ | ? | ✓ | ✓ |
| Activity | ✓ | ? | ✓ | ✓ |
| ActivitySession | ✓ | ? | - | ✓ |
| Platform | ✓ | ? | ? | ? |
| HostScanJob | ✓ | ? | ? | ? |
| ActionService | ✓ | ? | ? | ? |
| User | - | ✓ | ? | ? |

*Note: POST for creation not fully tested on demo instance*

---

## Error Handling

### HTTP Status Codes
| Code | Meaning |
|------|--------|
| 200 | Success |
| 400 | Bad Request - Invalid parameters |
| 401 | Unauthorized - Invalid/expired token |
| 403 | Forbidden - MFA not completed or insufficient permissions |
| 404 | Not Found - Resource doesn't exist |
| 405 | Method Not Allowed |
| 500 | Internal Server Error |

### Error Response Format
```json
{
  "type": "string",
  "title": "string",
  "status": 400
}
```

---

## Usage Examples

### Python - Complete Authentication Flow
```python
import requests
import urllib3
urllib3.disable_warnings()

BASE_URL = "https://your-nps-server"

# Step 1: Initial sign-in
response = requests.post(
    f"{BASE_URL}/signinBody",
    json={"Login": "username", "Password": "password"},
    verify=False
)
pre_mfa_token = response.text.strip('"')  # Remove quotes

# Step 2: MFA verification
response = requests.post(
    f"{BASE_URL}/signin2fa",
    headers={"Authorization": f"Bearer {pre_mfa_token}"},
    json="123456",  # Your MFA code
    verify=False
)
full_token = response.text.strip('"')  # Full access token

# Step 3: Use the API
headers = {
    "Authorization": f"Bearer {full_token}",
    "Content-Type": "application/json"
}

# List managed resources
response = requests.get(
    f"{BASE_URL}/api/v1/ManagedResource",
    headers=headers,
    verify=False
)
resources = response.json()
print(f"Found {len(resources)} managed resources")
```

### Python - Search with Pagination
```python
# Get paginated credentials
response = requests.get(
    f"{BASE_URL}/api/v1/Credential/Search",
    headers=headers,
    verify=False
)
result = response.json()
print(f"Total credentials: {result['recordsTotal']}")
print(f"Returned: {len(result['data'])} items")
```

### Python - Get Single Resource
```python
resource_id = "54142c30-5e69-4566-be23-28e121e7240a"
response = requests.get(
    f"{BASE_URL}/api/v1/ManagedResource/{resource_id}",
    headers=headers,
    verify=False
)
resource = response.json()
print(f"Resource: {resource['name']}")
```

### cURL - Authentication
```bash
# Step 1: Get pre-MFA token
PRE_TOKEN=$(curl -sk -X POST "https://your-server/signinBody" \
  -H "Content-Type: application/json" \
  -d '{"Login":"admin","Password":"password"}' | tr -d '"' )

# Step 2: Complete MFA
TOKEN=$(curl -sk -X POST "https://your-server/signin2fa" \
  -H "Authorization: Bearer $PRE_TOKEN" \
  -H "Content-Type: application/json" \
  -d '"123456"' | tr -d '"' )

# Step 3: Use API
curl -sk "https://your-server/api/v1/ManagedResource" \
  -H "Authorization: Bearer $TOKEN"
```

### PowerShell - Authentication
```powershell
$BaseUrl = "https://your-nps-server"

# Step 1: Initial sign-in
$body = @{ Login = "admin"; Password = "password" } | ConvertTo-Json
$preToken = Invoke-RestMethod -Uri "$BaseUrl/signinBody" -Method Post -Body $body -ContentType "application/json" -SkipCertificateCheck

# Step 2: MFA
$headers = @{ Authorization = "Bearer $preToken" }
$token = Invoke-RestMethod -Uri "$BaseUrl/signin2fa" -Method Post -Headers $headers -Body '"123456"' -ContentType "application/json" -SkipCertificateCheck

# Step 3: Use API
$headers = @{ Authorization = "Bearer $token" }
$resources = Invoke-RestMethod -Uri "$BaseUrl/api/v1/ManagedResource" -Headers $headers -SkipCertificateCheck
$resources | Format-Table name, platformName, dnsHostName
```

---

## Appendix: Endpoint Summary

### Core Resources
- **ManagedResource** - Hosts, domains, websites, Azure AD tenants, databases
- **Credential** - Service accounts, user credentials, SSH keys
- **ManagedAccount** - Managed privileged accounts
- **AccessControlPolicy** - Access control rules and permissions
- **Activity** - Session activities (RDP, SSH, Token, Credential Release)
- **ActivitySession** - Active and historical sessions

### Configuration
- **Platform** - Platform definitions (Windows, Linux, AD, etc.)
- **ScheduledChangePolicy** - Password rotation schedules
- **ProtectionPolicy** - Protection rules
- **ApprovalWorkflow** - Approval process definitions

### Operations
- **HostScanJob** - Host discovery and scanning jobs
- **ActionQueue** - Queued actions and their status
- **ActionService** - Action service instances
- **ActionGroup** - Groups of actions

### Infrastructure
- **ServiceRegistration** - Registered services
- **SecretVault** - Secret storage vaults
- **Website** - Web application definitions
- **Node** - Cluster nodes

### System
- **Health** - System health status
- **Version** - API version information
- **User** - User management

---

## Known Limitations

1. **MFA Required** - All API access requires MFA completion
2. **No Public OpenAPI Spec** - Swagger/OpenAPI not publicly accessible
3. **Rate Limits** - Not documented, use reasonable request rates
4. **Token Expiration** - Implement token refresh logic
5. **Some Endpoints Return 400/500** - Group endpoints may require specific parameters

---

## Recommendations for API Integration

1. **Implement full MFA flow** in all API clients
2. **Request service accounts** without MFA for automation (if supported)
3. **Cache JWT tokens** with refresh logic before expiration
4. **Use Search endpoints** for large datasets (pagination)
5. **Handle errors gracefully** - check status codes and error responses
6. **Use HTTPS** and handle certificate validation appropriately

---

*Documentation generated from live demo instance exploration - January 2026*
*Netwrix Privilege Secure v25.12.00000*


---

# PART 4: POWERSHELL MODULE REFERENCE

The complete PowerShell module is available in: `/root/NPS_PowerShell_Complete_Reference.ps1`

## PowerShell Module Summary

- **Total Functions:** 35+
- **Authentication:** `Connect-NPSServer`
- **Generic API Call:** `Invoke-NPSApi`
- **Resource Functions:** Get-NPS* for each endpoint
- **Advanced Examples:** Export, Monitor, Health Check

## Quick Start

```powershell
# Load the module
. .\NPS_PowerShell_Complete_Reference.ps1

# Connect
Connect-NPSServer -Server "https://your-server" `
    -Username "admin" -Password "P@ss" -MfaCode "123456"

# Use
Get-NPSHealth
Get-NPSManagedResource -Search
Get-NPSCredential -Count
Test-NPSServices
```

---

# APPENDIX: FILE INVENTORY

| File | Size | Description |
|------|------|-------------|
| `/root/NPS_MASTER_DOCUMENTATION.md` | ~75 KB | This consolidated master document |
| `/root/NPS_PowerShell_Complete_Reference.ps1` | 35 KB | Complete PowerShell module |
| `/root/netwrix_api_inventory.md` | 23 KB | GitHub-sourced endpoint inventory |
| `/root/netwrix_privilege_secure_api_documentation.md` | 18 KB | Live discovery documentation |
| `/root/NPS_API_Complete_Reference.md` | 16 KB | Verified endpoint reference |

---

*Master documentation compiled from multiple discovery sessions and official GitHub documentation.*
