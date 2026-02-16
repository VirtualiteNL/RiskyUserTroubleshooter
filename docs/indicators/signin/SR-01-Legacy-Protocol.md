# SR-01: Legacy Protocol (IMAP/POP/SMTP)

## Overview

| Property | Value |
|----------|-------|
| **ID** | SR-01 |
| **Name** | Legacy Protocol |
| **Points** | +3 |
| **Type** | Risk Indicator |
| **Module** | `ioc-signin-baselineiocs.ps1` |

## Description

Detects sign-ins using legacy authentication protocols (IMAP, POP, SMTP) that do not support modern authentication or Multi-Factor Authentication (MFA).

## Why This Matters

Legacy protocols are a significant security risk because:
- They cannot enforce MFA
- They are commonly exploited in password spray attacks
- They bypass Conditional Access policies that require modern auth

## Detection Logic

```powershell
# Check if ClientAppUsed matches legacy protocol patterns
if ($SignIn.ClientAppUsed -match 'imap|pop|smtp|other|unknown') {
    $score = 3
}
```

## Data Source

- **API**: Microsoft Graph Sign-In Logs
- **Field**: `ClientAppUsed`
- **Values that trigger**: `imap`, `pop`, `smtp`, `other`, `unknown`

## Example Scenarios

### Triggered (+3 points)
- User connects via Outlook configured with POP3
- Email client using IMAP to fetch emails
- Application sending emails via SMTP relay

### Not Triggered (0 points)
- Sign-in via Microsoft 365 web portal
- Outlook desktop with modern auth
- Mobile Outlook app

## Recommended Actions

1. Identify the application/device using legacy auth
2. Migrate to modern authentication methods
3. Consider blocking legacy auth via Conditional Access
4. If legitimate, document as known configuration

## Related Indicators

- SR-03: No MFA Used
- SR-04: Conditional Access Failure

## Configuration

```json
// config/settings.json
"SR-01": {
    "name": "Legacy Protocol",
    "points": 3,
    "description": "IMAP/POP/SMTP - no MFA possible"
}
```
