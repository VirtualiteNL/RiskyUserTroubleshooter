# SR-12: Device Change in Session

## Overview

| Property | Value |
|----------|-------|
| **ID** | SR-12 |
| **Name** | Device Change |
| **Points** | +1 |
| **Type** | Risk Indicator |
| **Module** | `sessions.ps1` |

## Description

Detects when browser or operating system changes within the same session (same CorrelationId). This may indicate session token being used on different device.

## Why This Matters

Device changes within a session may indicate:
- Session token theft and replay
- Browser extension manipulating user agent
- Legitimate multi-device usage
- Testing/development activity

## Detection Logic

```powershell
# Part of session analysis in sessions.ps1
$sessionDevices = $session.SignIns | Select-Object -Unique `
    DeviceDetail.Browser, DeviceDetail.OperatingSystem

if ($sessionDevices.Count -gt 1) {
    $SignIn.Session_DeviceChanged = $true
}
```

## Data Source

- **API**: Microsoft Graph Sign-In Logs
- **Fields**:
  - `CorrelationId`
  - `DeviceDetail.Browser`
  - `DeviceDetail.OperatingSystem`

## Example Scenarios

### Triggered (+1 point)
- Session shows Chrome/Windows then Safari/MacOS
- Same session from Edge and Firefox
- Mobile and desktop user agents in same session

### Not Triggered (0 points)
- Consistent browser/OS throughout session
- Different sessions from different devices (expected)

## Notes

This is a low-severity indicator because:
- Some apps legitimately use background processes
- Browser updates can change user agent mid-session
- Extensions may modify browser signature

## Recommended Actions

1. Review the specific browsers/OS detected
2. Check if timing makes sense for user
3. Consider with other session anomalies
4. Investigate if combined with SR-10 or SR-11

## Related Indicators

- SR-09: Session Anomaly
- SR-10: Country Switch
- SR-11: Multiple IPs

## Configuration

```json
// config/settings.json
"SR-12": {
    "name": "Device Change",
    "points": 1,
    "description": "Browser/OS switch during session"
}
```
