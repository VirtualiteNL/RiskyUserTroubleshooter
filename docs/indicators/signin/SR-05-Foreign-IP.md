# SR-05: Foreign IP + AbuseIPDB Score

## Overview

| Property | Value |
|----------|-------|
| **ID** | SR-05 |
| **Name** | Foreign IP |
| **Points** | +1 to +3 (variable) |
| **Type** | Risk Indicator |
| **Module** | `ioc-signin-abuseasn.ps1` |

## Description

Detects sign-ins from IP addresses outside the Netherlands, with points scaled based on the AbuseIPDB reputation score.

## Why This Matters

Foreign sign-ins may indicate:
- Compromised credentials used from abroad
- VPN/proxy usage (legitimate or malicious)
- Business travel (legitimate)
- Attacker access from overseas infrastructure

## Detection Logic

```powershell
# Check if location is non-NL
$isForeign = $SignIn.Location.CountryOrRegion -notin @("NL", "Netherlands")

if ($isForeign) {
    # Scale points based on AbuseIPDB score
    if ($abuseVal -lt 10)       { $score = 1 }
    elseif ($abuseVal -lt 26)   { $score = 1 }
    elseif ($abuseVal -lt 50)   { $score = 2 }
    else                        { $score = 3 }
}
```

## Data Source

- **API**: Microsoft Graph Sign-In Logs + AbuseIPDB API
- **Fields**:
  - `Location.CountryOrRegion`
  - `IpAddress` (used for AbuseIPDB lookup)
- **AbuseIPDB**: External API for IP reputation

## Scoring Matrix

| AbuseIPDB Score | Points |
|-----------------|--------|
| 0-9 | +1 |
| 10-25 | +1 |
| 26-49 | +2 |
| 50+ | +3 |

## Example Scenarios

### Triggered
- Sign-in from Germany with clean IP (+1)
- Sign-in from Russia with abuse score 45 (+2)
- Sign-in from known malicious IP in China (+3)

### Not Triggered (0 points)
- Sign-in from Netherlands
- Sign-in from Dutch IP address

## Recommended Actions

1. Verify if user was traveling
2. Check if user has VPN configured
3. Review other sign-ins from same IP
4. Consider blocking high-risk countries via CA

## Related Indicators

- SR-06: Suspicious IP (AbuseIPDB + ASN)
- SR-07: Impossible Travel
- SR-15: Location Netherlands (negative)

## Configuration

```json
// config/settings.json
"SR-05": {
    "name": "Foreign IP",
    "points": "1-3",
    "description": "Foreign location based on AbuseIPDB score"
}
```
