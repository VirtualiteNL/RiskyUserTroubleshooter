# SR-03: No MFA Used

## Overview

| Property | Value |
|----------|-------|
| **ID** | SR-03 |
| **Name** | No MFA Used |
| **Points** | +2 |
| **Type** | Risk Indicator |
| **Module** | `signinrisk.ps1` |

## Description

Detects successful sign-ins where no Multi-Factor Authentication was performed. This indicates the sign-in relied solely on username/password.

## Why This Matters

Sign-ins without MFA are more vulnerable to:
- Credential theft (phishing, password spray)
- Brute force attacks
- Credential stuffing from leaked databases

## Detection Logic

```powershell
# Check if no authentication details (MFA steps) were recorded
if ($SignIn.AuthenticationDetails.Count -eq 0) {
    $score = 2
}
```

## Data Source

- **API**: Microsoft Graph Sign-In Logs
- **Field**: `AuthenticationDetails`
- **Condition**: Array is empty or count is 0

## Example Scenarios

### Triggered (+2 points)
- User signs in from trusted network (MFA bypassed by CA)
- Legacy auth sign-in
- Application using app password

### Not Triggered (0 points)
- Sign-in completed with Authenticator app
- Sign-in with FIDO2 key
- Sign-in with Windows Hello

## Notes

This indicator has lower priority than SR-02 (MFA Failure). The scoring logic only adds SR-03 if SR-02 is not triggered, preventing double-counting.

## Recommended Actions

1. Review Conditional Access policies
2. Check if MFA bypass is intentional (trusted location)
3. Consider enforcing MFA for all sign-ins
4. If legitimate exception, document the reason

## Related Indicators

- UR-01: No MFA Registered
- SR-01: Legacy Protocol
- UR-10: CA Protection

## Configuration

```json
// config/settings.json
"SR-03": {
    "name": "No MFA Used",
    "points": 2,
    "description": "Unprotected login without MFA"
}
```
