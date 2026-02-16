# SR-06: Suspicious IP (AbuseIPDB + ASN)

## Overview

| Property | Value |
|----------|-------|
| **ID** | SR-06 |
| **Name** | Suspicious IP+ASN |
| **Points** | +3 |
| **Type** | Risk Indicator |
| **Module** | `ioc-signin-abuseasn.ps1` |

## Description

Detects sign-ins from IP addresses with both a high AbuseIPDB score (70+) AND an unknown/untrusted ASN (Autonomous System Number). This combination strongly indicates malicious infrastructure.

## Why This Matters

High abuse score + untrusted ASN indicates:
- Known malicious infrastructure
- Hosting provider commonly used for attacks
- VPS/cloud provider popular with attackers
- Proxy/VPN services used for anonymity

## Detection Logic

```powershell
# Trusted Dutch ISP whitelist
$trustedASNs = @("ziggo", "kpn", "t-mobile", "xs4all", "vodafone",
                 "tele2", "chello", "solcon", "caiway", "delta")

$asnIsUntrusted = $SignIn.ASN -and
    ($trustedASNs -notcontains $SignIn.ASN.ToLower())

# Only trigger if BOTH conditions are met
if ($abuseVal -ge 70 -and $asnIsUntrusted) {
    $score = 3
}
```

## Data Source

- **APIs**:
  - Microsoft Graph Sign-In Logs
  - AbuseIPDB API
  - IP-API (for ASN lookup)
- **Fields**:
  - `IpAddress`
  - `ASN` (enriched via API)
  - AbuseIPDB confidence score

## Example Scenarios

### Triggered (+3 points)
- Sign-in from IP with 85 abuse score on DigitalOcean
- Sign-in from IP with 72 abuse score on unknown VPS provider
- Sign-in from known bulletproof hosting IP

### Not Triggered (0 points)
- High abuse score but on KPN (trusted ASN)
- Low abuse score on unknown ASN
- Any sign-in from trusted Dutch ISP

## Trusted ASN Whitelist

The following Dutch ISPs are whitelisted:
- Ziggo
- KPN
- T-Mobile
- XS4ALL
- Vodafone
- Tele2
- Chello
- Solcon
- Caiway
- Delta

## Recommended Actions

1. **High Priority**: Investigate immediately
2. Block the IP address
3. Reset user credentials
4. Revoke all sessions
5. Review for data exfiltration

## Related Indicators

- SR-05: Foreign IP + AbuseIPDB Score
- SR-02: MFA Failure
- SR-07: Impossible Travel

## Configuration

```json
// config/settings.json
"SR-06": {
    "name": "Suspicious IP+ASN",
    "points": 3,
    "description": "High abuse score + unknown ASN"
}
```
