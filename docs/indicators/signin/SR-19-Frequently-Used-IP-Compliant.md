# SR-19: Frequently Used IP (Compliant Device)

## Overview

| Property | Value |
|----------|-------|
| **ID** | SR-19 |
| **Name** | Frequently Used IP (Compliant) |
| **Points** | **-2** (safety indicator) |
| **Type** | Safety Indicator |
| **Module** | `ioc-signin-trustedip.ps1` |

## Description

Reduces risk score when sign-in IP has been used 3+ times in the last 30 days with compliant device sign-ins.

## Why This Reduces Risk

IPs frequently used with compliant devices:
- Indicate managed, corporate environments
- Show consistent secure access patterns
- Likely represent office or approved locations
- Higher trust than MFA-only verification

## Detection Logic

```powershell
# Analyze sign-in history to build IP profile
$ipStats = $signins | Group-Object IpAddress | ForEach-Object {
    @{
        IP = $_.Name
        CompliantCount = ($_.Group | Where-Object {
            $_.DeviceDetail.IsCompliant -eq $true
        }).Count
    }
}

# Check current sign-in IP against profile
$ipStat = $ipStats | Where-Object { $_.IP -eq $SignIn.IpAddress }

if ($ipStat.CompliantCount -ge 3) {
    $score = -2
}
```

## Data Source

- **API**: Microsoft Graph Sign-In Logs
- **Fields**:
  - `IpAddress`
  - `DeviceDetail.IsCompliant`
- **Analysis Period**: Last 30 days

## Threshold

- **Minimum occurrences**: 3
- **Requirement**: Each occurrence must be from compliant device
- **Time window**: 30 days

## Example Scenarios

### Triggered (-2 points)
- Office network with regular compliant device access
- Corporate VPN used consistently with managed devices
- Home network with corporate laptop access pattern

### Not Triggered (0 points)
- IP used primarily with personal devices
- IP with less than 3 compliant device sign-ins
- New IP address not in history

## Scoring Rationale

This indicator awards -2 points (same as SR-17 Trusted Location) because:
- Compliant devices provide strong identity assurance
- Pattern of compliant access indicates controlled environment
- Higher trust than MFA alone (SR-18 = -1 point)

## Related Indicators

- SR-17: Trusted Location IP (-2 points)
- SR-18: Frequently Used IP with MFA (-1 point)
- SR-14: Compliant Device (-3 points)

## Configuration

```json
// config/settings.json
"SR-19": {
    "name": "Frequently Used IP (Compliant)",
    "points": -2,
    "description": "IP used 3+ times in last 30 days with compliant device - safety indicator"
}
```
