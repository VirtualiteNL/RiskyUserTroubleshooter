# UR-05: Suspicious Inbox Rules

## Overview

| Property | Value |
|----------|-------|
| **ID** | UR-05 |
| **Name** | Suspicious Inbox Rules |
| **Points** | +2 |
| **Type** | Risk Indicator |
| **Module** | `ioc-userrisk-inboxrules.ps1` |

## Description

Detects inbox rules that redirect or delete messages. These rules may be used by attackers to hide their activity or intercept communications.

## Why This Matters

Suspicious inbox rules can:
- Redirect emails to attacker's address
- Delete security notifications
- Hide evidence of compromise
- Intercept password reset emails

## Detection Logic

```powershell
# Get inbox rules
$rules = Get-InboxRule -Mailbox $UPN

# Filter for suspicious actions (excluding ForwardTo - covered by UR-04)
$suspiciousRules = $rules | Where-Object {
    $_.RedirectTo -or $_.DeleteMessage
}

if ($suspiciousRules.Count -gt 0) {
    $score = 2
}
```

## Data Source

- **API**: Exchange Online PowerShell
- **Cmdlet**: `Get-InboxRule`
- **Properties**: `RedirectTo`, `DeleteMessage`

## Suspicious Actions

| Action | Risk |
|--------|------|
| RedirectTo | Silently sends copy to another address |
| DeleteMessage | Permanently removes matching emails |

Note: `ForwardTo` is handled separately by UR-04.

## Example Scenarios

### Triggered (+2 points)
- Rule redirects password reset emails
- Rule deletes emails from IT security
- Rule moves all emails to Deleted Items

### Not Triggered (0 points)
- No redirect or delete rules
- Only normal organization rules

## Common Attacker Patterns

Attackers often create rules that:
- Delete emails containing "security", "suspicious", "password"
- Redirect emails from specific domains
- Move all emails to folders user won't check

## Recommended Actions

1. Review all inbox rules
2. Identify recently created rules
3. Check rule conditions and actions
4. Delete unauthorized rules
5. Investigate rule creation timing

## Related Indicators

- UR-04: Forwarding Enabled
- UR-06: OAuth Consents

## Configuration

```json
// config/settings.json
"UR-05": {
    "name": "Suspicious Inbox Rules",
    "points": 2,
    "description": "Rules that forward, redirect, or delete messages"
}
```
