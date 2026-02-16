# SR-11: Multiple IPs in Session

## Overview

| Property | Value |
|----------|-------|
| **ID** | SR-11 |
| **Name** | Multiple IPs |
| **Points** | +1 |
| **Type** | Risk Indicator |
| **Module** | `sessions.ps1` |

## Description

Detects when a single session (same CorrelationId) includes sign-ins from multiple IP addresses. This can indicate VPN usage, mobile network switching, or suspicious activity.

## Why This Matters

Multiple IPs in one session may indicate:
- Mobile device switching between WiFi and cellular
- VPN reconnection with different exit node
- Load balancer or proxy rotation
- Session being used from different networks

## Detection Logic

```powershell
# Part of session analysis in sessions.ps1
$sessionIPs = $session.SignIns | Select-Object -Unique IpAddress

if ($sessionIPs.Count -gt 1) {
    $SignIn.Session_IPChanged = $true
}
```

## Data Source

- **API**: Microsoft Graph Sign-In Logs
- **Fields**:
  - `CorrelationId`
  - `IpAddress`

## Example Scenarios

### Triggered (+1 point)
- Mobile user switches from office WiFi to 4G
- User reconnects VPN and gets different exit IP
- Corporate proxy with multiple egress points

### Not Triggered (0 points)
- All session activity from same IP
- Different sessions from different IPs (expected)

## Notes

This is a low-severity indicator because:
- Many legitimate scenarios cause IP changes
- Mobile devices frequently switch networks
- VPN reconnections are common

## Recommended Actions

1. Check if IP change is within same country
2. Review timing of IP changes
3. Consider in context with other indicators
4. No immediate action for isolated occurrence

## Related Indicators

- SR-09: Session Anomaly
- SR-10: Country Switch
- SR-12: Device Change

## Configuration

```json
// config/settings.json
"SR-11": {
    "name": "Multiple IPs",
    "points": 1,
    "description": "Multiple IPs in same session (VPN/proxy possible)"
}
```
