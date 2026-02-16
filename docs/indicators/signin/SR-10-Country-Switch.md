# SR-10: Country Switch During Session

## Overview

| Property | Value |
|----------|-------|
| **ID** | SR-10 |
| **Name** | Country Switch |
| **Points** | +2 |
| **Type** | Risk Indicator |
| **Module** | `sessions.ps1` |

## Description

Detects when a user's sign-in session includes activity from different countries. This is less severe than SR-09 (full session anomaly) but still noteworthy.

## Why This Matters

Country switches may indicate:
- VPN usage (legitimate or for anonymity)
- Travel during active session
- Session being used from multiple locations
- Possible credential sharing

## Detection Logic

```powershell
# Part of session analysis in sessions.ps1
# Groups sign-ins by CorrelationId
# Compares Location.CountryOrRegion across session

if ($session.Countries.Count -gt 1) {
    $SignIn.Session_CountryChanged = $true
}
```

## Data Source

- **API**: Microsoft Graph Sign-In Logs
- **Fields**:
  - `CorrelationId`
  - `Location.CountryOrRegion`

## Example Scenarios

### Triggered (+2 points)
- Session starts in Netherlands, later activity from Germany
- User on VPN with exit nodes in different countries

### Not Triggered (0 points)
- All session activity from same country
- Different sessions from different countries (expected)

## Distinction from SR-09

| Indicator | Scope | Points |
|-----------|-------|--------|
| SR-09 | Any session anomaly (IP/device/country) | +4 |
| SR-10 | Country switch specifically | +2 |

Note: If SR-09 triggers, SR-10 typically also applies as part of the anomaly detection.

## Recommended Actions

1. Verify if user is traveling
2. Check if using VPN with international exit
3. Review other session indicators
4. Consider in context with other signs

## Related Indicators

- SR-09: Session Anomaly
- SR-07: Impossible Travel
- SR-05: Foreign IP

## Configuration

```json
// config/settings.json
"SR-10": {
    "name": "Country Switch",
    "points": 2,
    "description": "Country changed during session"
}
```
