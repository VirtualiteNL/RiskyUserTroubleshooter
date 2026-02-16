# SR-07: Impossible Travel

## Overview

| Property | Value |
|----------|-------|
| **ID** | SR-07 |
| **Name** | Impossible Travel |
| **Points** | +4 |
| **Type** | Risk Indicator |
| **Module** | `ioc-signin-impossibletravel.ps1` |

## Description

Detects sign-ins from geographically distant locations within a timeframe that makes physical travel impossible (speed > 1000 km/h).

## Why This Matters

Impossible travel strongly indicates:
- Concurrent access from multiple locations
- Credential compromise with active attacker
- Session hijacking
- Stolen tokens being used elsewhere

## Detection Logic

```powershell
# Calculate travel speed between consecutive sign-ins
$distKm = Get-DistanceKm -Lat1 $loc1.Lat -Lon1 $loc1.Lon `
                         -Lat2 $loc2.Lat -Lon2 $loc2.Lon
$hours = ([datetime]$curr.CreatedDateTime -
          [datetime]$prev.CreatedDateTime).TotalHours
$speed = $distKm / $hours

# Flag if speed exceeds threshold (default 1000 km/h)
if ($speed -gt $SpeedLimitKmH) {
    $curr.ImpossibleTravelDetected = $true
}
```

## Data Source

- **APIs**:
  - Microsoft Graph Sign-In Logs
  - IP-API.com (geolocation)
- **Fields**:
  - `IpAddress`
  - `CreatedDateTime`
  - `Location.City`, `Location.CountryOrRegion`

## Calculation Method

1. Get GPS coordinates for each unique IP
2. Calculate Haversine distance between locations
3. Calculate time difference between sign-ins
4. Compute required speed: `distance / time`
5. Flag if speed > 1000 km/h

## Example Scenarios

### Triggered (+4 points)
- Amsterdam to New York in 30 minutes
- London to Tokyo in 2 hours
- Paris to Sydney in 4 hours

### Not Triggered (0 points)
- Same IP address (no travel)
- Amsterdam to Berlin in 8 hours (plausible by car)
- Speed < 1000 km/h

## Travel Details Captured

When triggered, the following details are stored:
- From location (city, country, IP)
- To location (city, country, IP)
- Distance in kilometers
- Time elapsed
- Calculated speed

## Recommended Actions

1. **Immediate**: Revoke all user sessions
2. Reset password
3. Review sign-in from both locations
4. Check for data access/exfiltration
5. Verify with user their actual location

## Related Indicators

- SR-09: Session Anomaly
- SR-06: Suspicious IP
- SR-02: MFA Failure

## Configuration

```json
// config/settings.json
"impossibleTravelSpeedKmh": 1000,

"SR-07": {
    "name": "Impossible Travel",
    "points": 4,
    "description": "Geographically impossible travel detected"
}
```
