# UR-01: No MFA Registered

## Overview

| Property | Value |
|----------|-------|
| **ID** | UR-01 |
| **Name** | No MFA Registered |
| **Points** | +3 |
| **Type** | Risk Indicator |
| **Module** | `ioc-userrisk-mfamethods.ps1` |

## Description

Detects user accounts that have no Multi-Factor Authentication methods registered. This is a critical security risk.

## Why This Matters

Accounts without MFA:
- Rely solely on password protection
- Are highly vulnerable to credential theft
- Cannot benefit from MFA-enforcing CA policies
- Are prime targets for attackers

## Detection Logic

```powershell
# Retrieve all MFA methods for user
$activeMfa = Get-UserMfaMethods -UserId $user.Id

# Check if any methods are registered
if ($activeMfa.Count -eq 0) {
    $score = 3
}
```

## Data Source

- **API**: Microsoft Graph Authentication Methods
- **Endpoints checked**:
  - `Get-MgUserAuthenticationPhoneMethod`
  - `Get-MgUserAuthenticationMicrosoftAuthenticatorMethod`
  - `Get-MgUserAuthenticationFido2Method`
  - `Get-MgUserAuthenticationWindowsHelloForBusinessMethod`

## MFA Methods Checked

| Method | API |
|--------|-----|
| Phone (SMS/Call) | PhoneMethod |
| Authenticator App | MicrosoftAuthenticatorMethod |
| FIDO2 Security Key | Fido2Method |
| Windows Hello | WindowsHelloForBusinessMethod |

## Example Scenarios

### Triggered (+3 points)
- New user who hasn't completed MFA registration
- User who removed all MFA methods
- Legacy account never configured for MFA

### Not Triggered (0 points)
- User with Authenticator app configured
- User with phone number for SMS verification
- User with any MFA method registered

## Recommended Actions

1. **Immediate**: Require user to register MFA
2. Review Conditional Access policies
3. Consider temporary access restrictions
4. Contact user to complete registration

## Related Indicators

- SR-03: No MFA Used
- UR-02: Recent MFA Change
- UR-10: CA Protection

## Configuration

```json
// config/settings.json
"UR-01": {
    "name": "No MFA Registered",
    "points": 3,
    "description": "Critical security risk - no MFA methods registered"
}
```
