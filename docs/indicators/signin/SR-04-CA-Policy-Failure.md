# SR-04: Conditional Access Policy Failure

## Overview

| Property | Value |
|----------|-------|
| **ID** | SR-04 |
| **Name** | CA Policy Failure |
| **Points** | +2 |
| **Type** | Risk Indicator |
| **Module** | `signinrisk.ps1` |

## Description

Detects sign-in attempts that failed due to Conditional Access policy violations. This indicates an attempted sign-in that was blocked by security policies.

## Why This Matters

CA failures indicate:
- Sign-in attempt from untrusted location/device
- Attempt to access blocked application
- User trying to bypass security controls
- Potential attacker testing access methods

## Detection Logic

```powershell
# Check Conditional Access status
if ($SignIn.ConditionalAccessStatus -in @('failure', 'unknownFutureValue')) {
    $score = 2
}
```

## Data Source

- **API**: Microsoft Graph Sign-In Logs
- **Field**: `ConditionalAccessStatus`
- **Values that trigger**: `failure`, `unknownFutureValue`

## Example Scenarios

### Triggered (+2 points)
- Sign-in from non-compliant device blocked
- Access attempt from blocked country
- Attempt to access app requiring specific conditions

### Not Triggered (0 points)
- Sign-in allowed by CA policies
- No CA policies applied to sign-in
- CA policy enforcement not evaluated

## Notes

This indicator has lower priority than SR-02 (MFA Failure). The scoring logic only adds SR-04 if neither SR-02 nor SR-03 is triggered.

## Recommended Actions

1. Review which CA policy blocked the sign-in
2. Determine if the block was appropriate
3. If legitimate user, help them meet requirements
4. If suspicious, investigate further

## Related Indicators

- UR-10: CA Protection
- SR-03: No MFA Used

## Configuration

```json
// config/settings.json
"SR-04": {
    "name": "CA Policy Failure",
    "points": 2,
    "description": "Conditional Access policy violation"
}
```
