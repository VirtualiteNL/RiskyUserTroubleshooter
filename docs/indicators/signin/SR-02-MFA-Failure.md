# SR-02: MFA Failure

## Overview

| Property | Value |
|----------|-------|
| **ID** | SR-02 |
| **Name** | MFA Failure |
| **Points** | +3 |
| **Type** | Risk Indicator |
| **Module** | `ioc-signin-mfafailure.ps1` |

## Description

Detects sign-in attempts where the password was correct but Multi-Factor Authentication (MFA) failed. This is a strong indicator that the password may be compromised.

## Why This Matters

MFA failures after successful password entry indicate:
- The attacker knows the correct password
- MFA is actively protecting the account
- The account is under active attack

## Detection Logic

```powershell
# Check for MFA-specific failure codes
$mfaFailureCodes = @(500121, 50074, 50076, 50079)

if ($SignIn.Status.ErrorCode -in $mfaFailureCodes -or
    $SignIn.Status.FailureReason -like "*multifactor*") {
    $score = 3
}
```

## Data Source

- **API**: Microsoft Graph Sign-In Logs
- **Fields**: `Status.ErrorCode`, `Status.FailureReason`
- **Error Codes**:
  - `500121`: Authentication failed during MFA challenge
  - `50074`: MFA required but not completed
  - `50076`: MFA required
  - `50079`: MFA registration required

## Example Scenarios

### Triggered (+3 points)
- Attacker enters correct password, cannot complete MFA
- User's MFA device is unavailable/compromised
- Automated attack trying to bypass MFA

### Not Triggered (0 points)
- Failed password attempt
- Successful sign-in with MFA
- Sign-in blocked by Conditional Access before MFA

## Recommended Actions

1. **Immediate**: Reset user's password
2. Revoke all active sessions
3. Review recent MFA method changes
4. Check for suspicious inbox rules or forwarding
5. Investigate the source IP addresses

## Related Indicators

- UR-02: Recent MFA Change
- SR-06: Suspicious IP (AbuseIPDB + ASN)
- SR-07: Impossible Travel

## Configuration

```json
// config/settings.json
"SR-02": {
    "name": "MFA Failure",
    "points": 3,
    "description": "Sign-in failed at MFA stage after valid credentials"
}
```
