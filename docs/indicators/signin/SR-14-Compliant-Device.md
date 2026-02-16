# SR-14: Compliant Device

## Overview

| Property | Value |
|----------|-------|
| **ID** | SR-14 |
| **Name** | Compliant Device |
| **Points** | **-3** (safety indicator) |
| **Type** | Safety Indicator |
| **Module** | `ioc-signin-baselineiocs.ps1` |

## Description

Reduces risk score when sign-in is from an Intune-compliant device. This is the strongest device-based safety indicator.

## Why This Reduces Risk

Intune-compliant devices:
- Meet organization's security requirements
- Have encryption enabled
- Run supported OS versions
- Have required security software
- Pass compliance policies

## Detection Logic

```powershell
# Check device compliance status
if ($SignIn.DeviceDetail.IsCompliant -eq $true) {
    $score = -3  # Negative = reduces risk
}
```

## Data Source

- **API**: Microsoft Graph Sign-In Logs
- **Field**: `DeviceDetail.IsCompliant`
- **Value**: `true`

## Compliance Requirements (Typical)

Intune compliance policies may require:
- BitLocker/FileVault encryption
- Minimum OS version
- Antivirus software active
- Firewall enabled
- Device not jailbroken/rooted
- Password/PIN configured

## Example Scenarios

### Triggered (-3 points)
- Sign-in from corporate laptop passing all compliance checks
- Sign-in from managed mobile device meeting policy

### Not Triggered (0 points)
- Sign-in from non-compliant device
- Sign-in from personal device
- Sign-in from device not enrolled in Intune

## Notes

This is the **strongest safety indicator** for devices. A compliant device provides high assurance that:
- The organization controls the device
- Security policies are enforced
- The device is in a known-good state

## Related Indicators

- SR-13: Trusted Device (-2 points)
- SR-15: Location Netherlands (-1 point)
- SR-19: Frequently Used IP with Compliant Device (-2 points)

## Configuration

```json
// config/settings.json
"SR-14": {
    "name": "Compliant Device",
    "points": -3,
    "description": "Intune compliant device - safety indicator"
}
```
