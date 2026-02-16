# SR-18: Frequently Used IP (MFA Verified)

## Overview

| Property | Value |
|----------|-------|
| **ID** | SR-18 |
| **Name** | Frequently Used IP (MFA) |
| **Points** | **-1** (safety indicator) |
| **Type** | Safety Indicator |
| **Module** | `ioc-signin-trustedip.ps1` |

## Description

Reduces risk score when sign-in IP has been used 3+ times in the last 30 days with successful MFA verification.

## Why This Reduces Risk

Frequently used IPs with MFA success:
- Indicate established, verified location
- Show consistent user behavior pattern
- Demonstrate legitimate access history
- Reduce likelihood of attacker IP

## Detection Logic

```powershell
# Analyze sign-in history to build IP profile
$ipStats = $signins | Group-Object IpAddress | ForEach-Object {
    @{
        IP = $_.Name
        MfaSuccessCount = ($_.Group | Where-Object {
            $_.AuthenticationDetails.Count -gt 0
        }).Count
    }
}

# Check current sign-in IP against profile
$ipStat = $ipStats | Where-Object { $_.IP -eq $SignIn.IpAddress }

if ($ipStat.MfaSuccessCount -ge 3) {
    $score = -1
}
```

## Data Source

- **API**: Microsoft Graph Sign-In Logs
- **Fields**:
  - `IpAddress`
  - `AuthenticationDetails` (MFA indicator)
- **Analysis Period**: Last 30 days

## Threshold

- **Minimum occurrences**: 3
- **Requirement**: Each occurrence must have MFA completion
- **Time window**: 30 days

## Example Scenarios

### Triggered (-1 point)
- User's home IP used 5 times with MFA
- Office IP with consistent MFA-verified sign-ins
- Regular VPN exit point with MFA history

### Not Triggered (0 points)
- New IP address (first time seen)
- IP used less than 3 times
- IP used without MFA (legacy auth)

## Profile Building

The trusted IP profile is built once per analysis session:
1. Collect all sign-ins for user (30 days)
2. Group by IP address
3. Count MFA-verified sign-ins per IP
4. Store in session cache

## Related Indicators

- SR-17: Trusted Location IP (-2 points)
- SR-19: Frequently Used IP with Compliant Device (-2 points)
- SR-14: Compliant Device (-3 points)

## Configuration

```json
// config/settings.json
"SR-18": {
    "name": "Frequently Used IP (MFA)",
    "points": -1,
    "description": "IP used 3+ times in last 30 days with successful MFA - safety indicator"
}
```
