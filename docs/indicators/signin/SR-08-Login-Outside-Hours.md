# SR-08: Login Outside Working Hours

## Overview

| Property | Value |
|----------|-------|
| **ID** | SR-08 |
| **Name** | Login Outside Hours |
| **Points** | +1 |
| **Type** | Risk Indicator |
| **Module** | `ioc-signin-baselineiocs.ps1` |

## Description

Detects sign-ins outside the user's inferred working hours. Working hours are calculated from the user's sign-in patterns over the last 30 days.

## Why This Matters

Off-hours sign-ins may indicate:
- Attacker activity when user is not watching
- Automated attacks running overnight
- Legitimate after-hours work (lower concern)

## Detection Logic

```powershell
# Get sign-in hour in local time
$hour = ([datetime]$SignIn.CreatedDateTime).ToLocalTime().Hour

# Check against working hours with 2-hour buffer
if ($hour -lt ($WorkingHours.Start - 2) -or
    $hour -gt ($WorkingHours.End + 2)) {
    $score = 1
}
```

## Data Source

- **API**: Microsoft Graph Sign-In Logs
- **Field**: `CreatedDateTime`
- **Analysis**: Historical sign-in patterns

## Working Hours Inference

The tool analyzes the user's sign-in history to determine typical working hours:
1. Collect all sign-in timestamps from last 30 days
2. Calculate most common active hours
3. Set Start/End times based on pattern
4. Apply 2-hour buffer for flexibility

Default fallback: 07:00 - 18:00

## Example Scenarios

### Triggered (+1 point)
- Sign-in at 03:00 AM (user typically works 09:00-17:00)
- Sign-in at 23:00 (outside normal pattern)

### Not Triggered (0 points)
- Sign-in at 10:00 during business hours
- Sign-in at 19:00 (within 2-hour buffer of 18:00 end)

## Notes

This is a low-severity indicator (+1 point) because:
- Many users legitimately work odd hours
- Traveling users may sign in at unusual times
- Should be considered in context with other indicators

## Recommended Actions

1. Review in context with other indicators
2. Check if timing pattern is consistent
3. Verify with user if unusual for them
4. No immediate action needed for isolated occurrence

## Related Indicators

- SR-07: Impossible Travel
- SR-09: Session Anomaly

## Configuration

```json
// config/settings.json
"workingHoursBufferHours": 2,
"workingHours": {
    "start": 7,
    "end": 18
},

"SR-08": {
    "name": "Login Outside Hours",
    "points": 1,
    "description": "Sign-in outside inferred working hours"
}
```
