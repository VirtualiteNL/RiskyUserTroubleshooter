# SR-15: Location Netherlands

## Overview

| Property | Value |
|----------|-------|
| **ID** | SR-15 |
| **Name** | Location Netherlands |
| **Points** | **-1** (safety indicator) |
| **Type** | Safety Indicator |
| **Module** | `ioc-signin-baselineiocs.ps1` |

## Description

Reduces risk score when sign-in originates from the Netherlands, the expected location for users of Dutch organizations.

## Why This Reduces Risk

Sign-ins from Netherlands:
- Match expected user location
- Are less likely to be from foreign attackers
- Indicate normal usage pattern

## Detection Logic

```powershell
# Check if location is Netherlands
if ($SignIn.Location.CountryOrRegion -in @("NL", "Netherlands")) {
    $score = -1  # Negative = reduces risk
}
```

## Data Source

- **API**: Microsoft Graph Sign-In Logs
- **Field**: `Location.CountryOrRegion`
- **Values**: `NL` or `Netherlands`

## Example Scenarios

### Triggered (-1 point)
- Sign-in from Amsterdam
- Sign-in from any Dutch city
- Sign-in with Dutch IP address

### Not Triggered (0 points)
- Sign-in from Germany
- Sign-in from any non-Dutch location

## Customization Note

This indicator is Netherlands-specific. Organizations in other countries should modify the expected location in the code:

```powershell
# Example for German organization:
if ($SignIn.Location.CountryOrRegion -in @("DE", "Germany")) {
    $score = -1
}
```

## Related Indicators

- SR-05: Foreign IP (+1 to +3 points)
- SR-17: Trusted Location IP (-2 points)

## Configuration

```json
// config/settings.json
"SR-15": {
    "name": "Location Netherlands",
    "points": -1,
    "description": "Sign-in from expected location"
}
```
