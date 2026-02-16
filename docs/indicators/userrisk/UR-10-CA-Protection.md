# UR-10: CA Protection

## Overview

| Property | Value |
|----------|-------|
| **ID** | UR-10 |
| **Name** | CA Protection |
| **Points** | 0 to +3 (variable) |
| **Type** | Risk/Safety Indicator |
| **Module** | `ioc-userrisk-ca.ps1` |

## Description

Evaluates whether the user is protected by Conditional Access policies that enforce MFA or device requirements. Also detects if user is protected by block policies as alternative protection.

## Why This Matters

Conditional Access protection:
- Enforces security requirements
- Blocks risky access attempts
- Ensures MFA is used
- Provides defense in depth

## Detection Logic

```powershell
# Get all enabled CA policies
$enabledPolicies = Get-CAPolicy | Where-Object { $_.state -eq "enabled" }

# Filter protective policies (MFA, device compliance)
$protectivePolicies = $enabledPolicies | Where-Object {
    $_.grantControls.builtInControls -contains "mfa" -or
    $_.grantControls.builtInControls -contains "compliantDevice" -or
    $_.grantControls.builtInControls -contains "domainJoinedDevice"
}

# Filter block policies
$blockPolicies = $enabledPolicies | Where-Object {
    $_.grantControls.builtInControls -contains "block"
}

# Evaluate user's protection status
if ($userProtectedByMFA) {
    if ($allAppsCovered) {
        return @{ Points = 0; Status = "Full" }
    } else {
        return @{ Points = 2; Status = "Partial" }
    }
} elseif ($userProtectedByBlock) {
    return @{ Points = 1; Status = "Block policy only" }
} else {
    return @{ Points = 3; Status = "None" }
}
```

## Data Source

- **API**: Microsoft Graph Conditional Access
- **Endpoint**: `/identity/conditionalAccess/policies`
- **Analysis**: User/group membership, policy conditions

## Protection Levels

| Status | Points | Meaning |
|--------|--------|---------|
| Full | 0 | Protected by MFA policy for all apps |
| Partial | +2 | Protected but not all apps covered |
| Block policy only | +1 | No MFA policy, but has block policy |
| None | +3 | Not protected by any CA policy |

## Block Policy Detection (New)

The tool now detects when users are protected by block policies:
- User excluded from MFA policies
- BUT included in a block policy
- Provides alternative protection
- Shows policy name in report

## Example Scenarios

### Full Protection (0 points)
- User covered by "Require MFA for all users"
- Policy applies to all cloud apps

### Partial Protection (+2 points)
- MFA required for some apps
- But Office 365 excluded from policy

### Block Policy Only (+1 point)
- User excluded from MFA policies
- But covered by "Block all except trusted locations"

### No Protection (+3 points)
- No CA policies apply to user
- User excluded from all security policies

## Recommended Actions

| Status | Action |
|--------|--------|
| Full | No action needed |
| Partial | Expand CA coverage |
| Block only | Consider adding MFA policy |
| None | Add user to CA policies immediately |

## Related Indicators

- UR-01: No MFA Registered
- SR-03: No MFA Used
- SR-04: CA Policy Failure

## Configuration

```json
// config/settings.json
"UR-10": {
    "name": "CA Protection",
    "points": "0-3",
    "description": "Conditional Access protection status"
}
```
