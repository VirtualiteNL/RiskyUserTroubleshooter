# UR-04: Forwarding Enabled

## Overview

| Property | Value |
|----------|-------|
| **ID** | UR-04 |
| **Name** | Forwarding Enabled |
| **Points** | +3 |
| **Type** | Risk Indicator |
| **Module** | `ioc-userrisk-forwarding.ps1` |

## Description

Detects when mailbox forwarding is configured, either at the mailbox level or through inbox rules. This is a high-risk indicator for data exfiltration.

## Why This Matters

Email forwarding is a common attacker technique:
- Exfiltrate all incoming email silently
- Maintain access even after password reset
- Capture sensitive business communications
- Often goes unnoticed by user

## Detection Logic

```powershell
# Check mailbox-level forwarding
$mailbox = Get-Mailbox -Identity $UPN
$hasMailboxForwarding = $mailbox.ForwardingSmtpAddress -ne $null

# Check inbox rules with ForwardTo
$rules = Get-InboxRule -Mailbox $UPN
$forwardingRules = $rules | Where-Object { $_.ForwardTo }

if ($hasMailboxForwarding -or $forwardingRules.Count -gt 0) {
    $score = 3
}
```

## Data Source

- **API**: Exchange Online PowerShell
- **Cmdlets**:
  - `Get-Mailbox` (ForwardingSmtpAddress)
  - `Get-InboxRule` (ForwardTo action)

## Forwarding Types

| Type | Source | Detection |
|------|--------|-----------|
| Mailbox Forwarding | Mailbox settings | `ForwardingSmtpAddress` |
| Inbox Rule Forward | Inbox rules | `ForwardTo` property |

## Example Scenarios

### Triggered (+3 points)
- Mailbox forwards all email to external address
- Inbox rule forwards specific emails to attacker
- Auto-forward to personal email configured

### Not Triggered (0 points)
- No forwarding configured
- Only internal forwarding (may still be flagged)

## Popup Display

The report shows:
- Source (Mailbox Setting or Inbox Rule)
- Forward destination address
- Whether original is kept (DeliverToMailboxAndForward)

## Recommended Actions

1. **Immediate**: Disable forwarding
2. Review destination addresses
3. Check when forwarding was configured
4. Search for exfiltrated data
5. Consider security incident

## Related Indicators

- UR-05: Suspicious Inbox Rules
- UR-03: Mailbox Delegates

## Configuration

```json
// config/settings.json
"UR-04": {
    "name": "Forwarding Enabled",
    "points": 3,
    "description": "High exfiltration risk - email forwarding configured"
}
```
