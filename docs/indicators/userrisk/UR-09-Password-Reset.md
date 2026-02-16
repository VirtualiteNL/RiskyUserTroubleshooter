# UR-09: Password Reset (< 30 Days)

## Overview

| Property | Value |
|----------|-------|
| **ID** | UR-09 |
| **Name** | Password Reset |
| **Points** | +1 |
| **Type** | Risk Indicator |
| **Module** | `ioc-userrisk-passwordreset.ps1` |

## Description

Detects when the user's password was reset within the last 30 days. This may indicate response to a security incident or attacker activity.

## Why This Matters

Recent password resets may indicate:
- User suspected compromise and reset
- IT responded to security alert
- Attacker reset to gain access
- Self-service reset after forgotten password

## Detection Logic

```powershell
# Search audit logs for password reset events
$pwdResetActivities = @(
    "Reset user password",
    "Reset password (self-service)",
    "Change user password",
    "Change password (self-service)"
)

$pwdEvents = $global:UserDirectoryAuditLogs | Where-Object {
    $_.ActivityDisplayName -in $pwdResetActivities
}

if ($pwdEvents.Count -gt 0) {
    $score = 1
}
```

## Data Source

- **API**: Microsoft Graph Audit Logs
- **Activities**: Password reset/change events
- **Time window**: Last 30 days

## Audit Events Monitored

| Event | Initiated By |
|-------|--------------|
| Reset user password | Admin |
| Reset password (self-service) | User |
| Change user password | Admin |
| Change password (self-service) | User |

## Example Scenarios

### Triggered (+1 point)
- User reset password via SSPR
- Admin reset password after support call
- Password changed due to suspected breach

### Not Triggered (0 points)
- No password changes in 30 days
- Password stable

## Context Considerations

This is a lower-severity indicator because:
- Password resets are common
- May be routine IT operation
- Self-service reset after vacation
- Should check who initiated

## Popup Display

The report shows:
- Reset date/time
- Who initiated the reset

## Recommended Actions

1. Verify who initiated the reset
2. Check if user requested reset
3. Review timing against other indicators
4. Confirm no unauthorized access

## Related Indicators

- UR-02: Recent MFA Change
- SR-02: MFA Failure

## Configuration

```json
// config/settings.json
"UR-09": {
    "name": "Password Reset",
    "points": 1,
    "description": "Password reset within last 30 days"
}
```
