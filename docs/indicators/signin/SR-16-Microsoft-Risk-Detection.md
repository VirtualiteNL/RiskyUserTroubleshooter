# SR-16: Microsoft Risk Detection

## Overview

| Property | Value |
|----------|-------|
| **ID** | SR-16 |
| **Name** | Microsoft Risk Detection |
| **Points** | +2 to +4 (variable) |
| **Type** | Risk Indicator |
| **Module** | `signinrisk.ps1` |
| **Requires** | Entra ID P2 License |

## Description

Incorporates Microsoft Identity Protection risk signals into the scoring. These are advanced threat detections from Microsoft's security intelligence.

## Why This Matters

Microsoft Identity Protection detects:
- Known leaked credentials
- Password spray attacks
- Suspicious sign-in patterns
- Impossible travel (Microsoft's detection)
- Threat intelligence matches

## Detection Logic

```powershell
# Check Microsoft risk signals (P2 only)
$msRiskLevel = $SignIn.RiskLevelDuringSignIn
$msRiskDetail = $SignIn.RiskDetail

if ($msRiskLevel -notin @('none', 'hidden', $null)) {
    # Assign points based on severity
    $score = switch ($msRiskLevel) {
        'high'   { 4 }
        'medium' { 2 }
        'low'    { 1 }
        default  { 0 }
    }
}
```

## Data Source

- **API**: Microsoft Graph Sign-In Logs
- **Fields**:
  - `RiskLevelDuringSignIn`
  - `RiskDetail`
- **License**: Requires Entra ID P2

## Risk Types Detected

| Risk Detail | Description |
|-------------|-------------|
| leakedCredentials | Password found in breach database |
| maliciousIPAddress | Known malicious IP |
| passwordSpray | Password spray attack detected |
| tokenIssuerAnomaly | Token from suspicious issuer |
| unfamiliarFeatures | Unusual sign-in characteristics |
| anonymizedIPAddress | VPN/Tor detected |
| impossibleTravel | Microsoft's travel detection |

## Scoring Matrix

| Microsoft Risk Level | Points |
|---------------------|--------|
| High | +4 |
| Medium | +2 |
| Low | +1 |
| None/Hidden | 0 |

## Example Scenarios

### Triggered
- Microsoft detects leaked credentials (+4)
- Sign-in from anonymous IP flagged by MS (+2)
- Low-confidence unusual sign-in (+1)

### Not Triggered (0 points)
- No Entra ID P2 license
- Risk level is 'none'
- Risk data not available

## License Requirement

This indicator **requires Entra ID P2** license. Without P2:
- `RiskLevelDuringSignIn` returns `null`
- No risk signals are available
- Indicator will not trigger

## Recommended Actions

When Microsoft flags high risk:
1. Treat as confirmed threat
2. Reset password immediately
3. Revoke all sessions
4. Enable enhanced monitoring
5. Review Microsoft's detailed risk report

## Related Indicators

- SR-07: Impossible Travel
- SR-02: MFA Failure
- SR-06: Suspicious IP

## Configuration

```json
// config/settings.json
"SR-16": {
    "name": "Microsoft Risk Detection",
    "points": "2-4",
    "description": "Microsoft Identity Protection risk signals",
    "requiresP2": true
}
```
