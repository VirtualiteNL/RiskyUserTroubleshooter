# SR-17: Trusted Location IP

## Overview

| Property | Value |
|----------|-------|
| **ID** | SR-17 |
| **Name** | Trusted Location IP |
| **Points** | **-2** (safety indicator) |
| **Type** | Safety Indicator |
| **Module** | `ioc-signin-trustedip.ps1` |

## Description

Reduces risk score when sign-in IP address is within a Conditional Access Named Location that is marked as "trusted".

## Why This Reduces Risk

Trusted Named Locations:
- Are explicitly configured by IT as safe
- Typically include corporate office IPs
- May include VPN exit points
- Represent known, authorized network ranges

## Detection Logic

```powershell
# Get CA Named Locations marked as trusted
$trustedLocations = Get-MgIdentityConditionalAccessNamedLocation -All |
    Where-Object { $_.AdditionalProperties.isTrusted -eq $true }

# Extract IP ranges from trusted locations
$trustedIpRanges = foreach ($location in $trustedLocations) {
    if ($location.AdditionalProperties.'@odata.type' -eq '#microsoft.graph.ipNamedLocation') {
        $location.AdditionalProperties.ipRanges
    }
}

# Check if sign-in IP is in any trusted range
$result = Test-IpInTrustedLocation -IpAddress $SignIn.IpAddress `
    -TrustedRanges $trustedIpRanges

if ($result.IsTrusted) {
    $score = -2
}
```

## Data Source

- **APIs**:
  - Microsoft Graph Identity CA Named Locations
  - Sign-In Logs
- **Fields**:
  - Named Location `isTrusted` flag
  - Named Location `ipRanges` (CIDR format)
  - Sign-in `IpAddress`

## CIDR Matching

The module supports both IPv4 and IPv6 CIDR notation:
- IPv4: `192.168.1.0/24`
- IPv6: `2001:db8::/32`

## Example Scenarios

### Triggered (-2 points)
- Sign-in from office IP range configured as trusted
- Sign-in from corporate VPN exit point
- Sign-in from partner network marked trusted

### Not Triggered (0 points)
- Sign-in from home network
- Sign-in from public WiFi
- Sign-in from IP not in any Named Location

## Setup Requirements

For this indicator to work:
1. Configure Named Locations in Entra ID
2. Mark appropriate locations as "Trusted"
3. Include IP ranges in CIDR format

## Related Indicators

- SR-15: Location Netherlands (-1 point)
- SR-18: Frequently Used IP with MFA (-1 point)
- SR-05: Foreign IP (+1-3 points)

## Configuration

```json
// config/settings.json
"SR-17": {
    "name": "Trusted Location IP",
    "points": -2,
    "description": "IP is in CA Named Location marked as trusted - safety indicator"
}
```
