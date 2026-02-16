# SR-13: Trusted Device (Azure AD Joined)

## Overview

| Property | Value |
|----------|-------|
| **ID** | SR-13 |
| **Name** | Trusted Device |
| **Points** | **-2** (safety indicator) |
| **Type** | Safety Indicator |
| **Module** | `ioc-signin-baselineiocs.ps1` |

## Description

Reduces risk score when sign-in is from an Azure AD joined device. This indicates the device is managed and trusted by the organization.

## Why This Reduces Risk

Azure AD joined devices:
- Are registered and managed by IT
- Have device identity verified by Azure AD
- Are subject to device compliance policies
- Provide higher assurance of legitimate access

## Detection Logic

```powershell
# Check device trust type
if ($SignIn.DeviceDetail.TrustType -eq "Azure AD joined") {
    $score = -2  # Negative = reduces risk
}
```

## Data Source

- **API**: Microsoft Graph Sign-In Logs
- **Field**: `DeviceDetail.TrustType`
- **Value**: `Azure AD joined`

## Trust Type Values

| Value | Meaning |
|-------|---------|
| Azure AD joined | Corporate device joined to Azure AD |
| Hybrid Azure AD joined | On-prem AD + Azure AD |
| Azure AD registered | Personal device registered (BYOD) |
| (empty) | Unknown/unmanaged device |

## Example Scenarios

### Triggered (-2 points)
- Sign-in from corporate laptop joined to Azure AD
- Sign-in from company-managed Windows 11 device

### Not Triggered (0 points)
- Sign-in from personal device
- Sign-in from unmanaged device
- Sign-in from hybrid joined device (different indicator)

## Notes

This is a **safety indicator** that reduces the overall risk score. It's one of several negative-scoring indicators that help identify legitimate access.

## Related Indicators

- SR-14: Compliant Device (-3 points)
- SR-15: Location Netherlands (-1 point)
- SR-17: Trusted Location IP (-2 points)

## Configuration

```json
// config/settings.json
"SR-13": {
    "name": "Trusted Device",
    "points": -2,
    "description": "Azure AD joined device - safety indicator"
}
```
