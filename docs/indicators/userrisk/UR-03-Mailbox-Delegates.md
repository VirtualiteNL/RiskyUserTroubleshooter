# UR-03: Mailbox Delegates

## Overview

| Property | Value |
|----------|-------|
| **ID** | UR-03 |
| **Name** | Mailbox Delegates |
| **Points** | +1 |
| **Type** | Risk Indicator |
| **Module** | `userrisk.ps1` |

## Description

Detects when other users have delegate access to the mailbox. While often legitimate, this increases the attack surface.

## Why This Matters

Mailbox delegation:
- Allows others to read/send as user
- May be exploited for data access
- Increases number of potential access points
- Can hide attacker activity

## Detection Logic

```powershell
# Get mailbox permissions
$mbxPermissions = Get-MailboxPermission -Identity $UPN |
    Where-Object {
        $_.User -notlike "NT AUTHORITY\*" -and
        $_.User -notlike "S-1-*" -and
        $_.IsInherited -eq $false
    }

if ($mbxPermissions.Count -gt 0) {
    $score = 1
}
```

## Data Source

- **API**: Exchange Online PowerShell
- **Cmdlet**: `Get-MailboxPermission`
- **Filters**: Excludes system accounts and inherited permissions

## Permission Types

| Permission | Description |
|------------|-------------|
| FullAccess | Read all mail, send on behalf |
| SendAs | Send email appearing as user |
| SendOnBehalf | Send email on behalf of user |

## Example Scenarios

### Triggered (+1 point)
- Executive assistant has FullAccess
- Manager can SendAs for team member
- Shared mailbox with multiple delegates

### Not Triggered (0 points)
- No delegate permissions configured
- Only system/inherited permissions

## Notes

This is a lower-severity indicator because:
- Delegation is common business practice
- Executive assistants often need access
- Should be verified, not alarming

## Recommended Actions

1. Review who has delegate access
2. Verify business justification
3. Check if delegates are appropriate
4. Remove unnecessary permissions

## Related Indicators

- UR-04: Forwarding Enabled
- UR-05: Suspicious Inbox Rules
- UR-06: OAuth Consents

## Configuration

```json
// config/settings.json
"UR-03": {
    "name": "Mailbox Delegates",
    "points": 1,
    "description": "Mailbox has shared/delegate access"
}
```
