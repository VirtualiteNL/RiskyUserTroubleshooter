# UR-08: New Account (< 7 Days)

## Overview

| Property | Value |
|----------|-------|
| **ID** | UR-08 |
| **Name** | New Account |
| **Points** | +2 |
| **Type** | Risk Indicator |
| **Module** | `ioc-userrisk-newaccount.ps1` |

## Description

Detects when the user account was created within the last 7 days. New accounts may be created by attackers or lack proper security configuration.

## Why This Matters

New accounts:
- May be created by attackers for persistence
- Might not have completed security setup
- Lack established behavior baseline
- Could indicate compromised admin creating accounts

## Detection Logic

```powershell
# Get account creation date
$createdDate = $user.CreatedDateTime

# Calculate account age
$accountAge = (Get-Date) - [datetime]$createdDate

if ($accountAge.TotalDays -lt 7) {
    $score = 2
}
```

## Data Source

- **API**: Microsoft Graph Users
- **Field**: `CreatedDateTime`
- **Threshold**: 7 days (configurable)

## Example Scenarios

### Triggered (+2 points)
- Account created yesterday
- New hire account created 3 days ago
- Service account created this week

### Not Triggered (0 points)
- Account older than 7 days
- Established user accounts

## Configuration

The threshold is configurable in settings.json:

```json
{
    "newAccountThresholdDays": 7
}
```

## Context Considerations

New accounts trigger this indicator but:
- May be legitimate new hires
- Could be planned service accounts
- Should be verified against HR records
- Worth investigating if unexpected

## Recommended Actions

1. Verify account creation was authorized
2. Check who created the account
3. Review if proper onboarding completed
4. Ensure security policies applied
5. Investigate if unexpected account

## Related Indicators

- UR-01: No MFA Registered
- UR-07: Active Admin Role

## Configuration

```json
// config/settings.json
"UR-08": {
    "name": "New Account",
    "points": 2,
    "description": "Account created within last 7 days"
}
```
