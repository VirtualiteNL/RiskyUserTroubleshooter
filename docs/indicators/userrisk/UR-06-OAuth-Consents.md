# UR-06: OAuth Consents

## Overview

| Property | Value |
|----------|-------|
| **ID** | UR-06 |
| **Name** | OAuth Consents |
| **Points** | +2 |
| **Type** | Risk Indicator |
| **Module** | `ioc-userrisk-oauthconsent.ps1` |

## Description

Detects third-party applications that have been granted access to the user's account through OAuth consent. Malicious apps may use this access for data theft.

## Why This Matters

OAuth consents can:
- Grant persistent access to mailbox
- Allow reading all emails
- Enable sending email as user
- Access calendar, contacts, files
- Survive password resets

## Detection Logic

```powershell
# Search audit logs for OAuth consent events
$oauthConsents = $global:UserDirectoryAuditLogs | Where-Object {
    $_.ActivityDisplayName -eq "Consent to application" -or
    $_.ActivityDisplayName -like "*consent*"
}

# Analyze granted permissions
foreach ($consent in $oauthConsents) {
    # Extract app name and permissions
    $appName = $consent.TargetResources[0].DisplayName
    $permissions = $consent.ModifiedProperties
}

if ($oauthConsents.Count -gt 0) {
    $score = 2
}
```

## Data Source

- **API**: Microsoft Graph Audit Logs
- **Activity**: "Consent to application"
- **Details**: TargetResources, ModifiedProperties

## Permission Scopes to Watch

| Scope | Risk Level | Access Granted |
|-------|------------|----------------|
| Mail.Read | High | Read all email |
| Mail.Send | High | Send email as user |
| Contacts.Read | Medium | Read contacts |
| Calendars.Read | Medium | Read calendar |
| Files.ReadWrite | High | Access OneDrive |

## Example Scenarios

### Triggered (+2 points)
- User consented to suspicious app
- Third-party mail client granted access
- Unknown app with mail permissions

### Not Triggered (0 points)
- No OAuth consents in audit period
- Only Microsoft first-party apps

## Popup Display

The report shows:
- Application display name
- Consent type
- Risk level assessment

## Consent Attacks

Common attack patterns:
- Phishing link leads to OAuth consent page
- Legitimate-looking app requests excessive permissions
- App name mimics known software

## Recommended Actions

1. Review all consented applications
2. Check when consent was granted
3. Verify app is legitimate
4. Revoke suspicious app access
5. Report malicious apps to Microsoft

## Related Indicators

- UR-04: Forwarding Enabled
- UR-05: Suspicious Inbox Rules

## Configuration

```json
// config/settings.json
"UR-06": {
    "name": "OAuth Consents",
    "points": 2,
    "description": "Third-party application access granted"
}
```
