# UR-02: Recent MFA Change

## Overview

| Property | Value |
|----------|-------|
| **ID** | UR-02 |
| **Name** | Recent MFA Change |
| **Points** | +1 |
| **Type** | Risk Indicator |
| **Module** | `ioc-userrisk-mfamodified.ps1` |

## Description

Detects when MFA methods have been modified within the last 30 days. This may indicate an attacker attempting to establish persistence.

## Why This Matters

Recent MFA changes may indicate:
- Attacker adding their own MFA method
- Attacker removing legitimate MFA
- Preparation for account takeover
- User legitimately updating methods

## Detection Logic

```powershell
# Search audit logs for MFA-related activities
$mfaActivities = @(
    "User registered security info",
    "User deleted security info",
    "User changed default security info",
    "Admin registered security info",
    "Admin deleted security info"
)

$recentMfaChanges = $global:UserDirectoryAuditLogs | Where-Object {
    $_.ActivityDisplayName -in $mfaActivities
}

if ($recentMfaChanges.Count -gt 0) {
    $score = 1
}
```

## Data Source

- **API**: Microsoft Graph Audit Logs
- **Filter**: `activityDisplayName` matching MFA activities
- **Time window**: Last 30 days

## Audit Activities Monitored

| Activity | Initiated By |
|----------|--------------|
| User registered security info | User |
| User deleted security info | User |
| User changed default security info | User |
| Admin registered security info | Admin |
| Admin deleted security info | Admin |

## Example Scenarios

### Triggered (+1 point)
- User added new phone number for MFA
- Admin reset user's MFA methods
- User registered new Authenticator app

### Not Triggered (0 points)
- No MFA changes in last 30 days
- MFA configuration unchanged

## Context Considerations

This is a lower-severity indicator because:
- Users legitimately update MFA (new phone, etc.)
- IT may reset MFA for support requests
- Should be evaluated with other indicators

## Recommended Actions

1. Review who initiated the MFA change
2. Verify change was authorized
3. Check timing against suspicious sign-ins
4. Confirm with user if unexpected

## Related Indicators

- UR-01: No MFA Registered
- SR-02: MFA Failure
- UR-09: Password Reset

## Configuration

```json
// config/settings.json
"UR-02": {
    "name": "Recent MFA Change",
    "points": 1,
    "description": "MFA methods modified recently - potentially suspicious"
}
```
