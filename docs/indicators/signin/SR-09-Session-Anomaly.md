# SR-09: Session Anomaly

## Overview

| Property | Value |
|----------|-------|
| **ID** | SR-09 |
| **Name** | Session Anomaly |
| **Points** | +4 |
| **Type** | Risk Indicator |
| **Module** | `signinrisk.ps1` / `sessions.ps1` |

## Description

Detects sessions where the IP address, device, or country changed within the same session (same CorrelationId). This is a strong indicator of session hijacking or token theft.

## Why This Matters

Session anomalies indicate:
- Possible session hijacking
- Stolen authentication tokens
- Man-in-the-middle attacks
- Concurrent access by attacker

## Detection Logic

```powershell
# Check session flags set by sessions.ps1
if ($SignIn.Session_CountryChanged -or
    $SignIn.Session_IPChanged -or
    $SignIn.Session_DeviceChanged) {
    $score = 4
}
```

## Session Analysis Process

The `sessions.ps1` module:
1. Groups sign-ins by `CorrelationId`
2. Compares attributes within each session
3. Flags anomalies:
   - `Session_CountryChanged`: Different countries
   - `Session_IPChanged`: Different IP addresses
   - `Session_DeviceChanged`: Different browser/OS

## Data Source

- **API**: Microsoft Graph Sign-In Logs
- **Fields**:
  - `CorrelationId`
  - `IpAddress`
  - `Location.CountryOrRegion`
  - `DeviceDetail.Browser`
  - `DeviceDetail.OperatingSystem`

## Example Scenarios

### Triggered (+4 points)
- Same session shows sign-ins from NL and US
- Same session shows Windows and MacOS
- Session starts on IP A, continues on IP B

### Not Triggered (0 points)
- All sign-ins in session from same IP
- Consistent device throughout session
- Different sessions (different CorrelationId)

## Session Anomaly Types

| Flag | Description | Severity |
|------|-------------|----------|
| Session_CountryChanged | Country switched during session | High |
| Session_IPChanged | IP address changed | Medium |
| Session_DeviceChanged | Browser/OS changed | Medium |

## Recommended Actions

1. **Immediate**: Revoke all user sessions
2. Reset password
3. Investigate both endpoints
4. Check for stolen tokens
5. Review affected timeframe for data access

## Related Indicators

- SR-10: Country Switch
- SR-11: Multiple IPs
- SR-12: Device Change
- SR-07: Impossible Travel

## Configuration

```json
// config/settings.json
"SR-09": {
    "name": "Session Anomaly",
    "points": 4,
    "description": "IP/device/country mismatch in session"
}
```
