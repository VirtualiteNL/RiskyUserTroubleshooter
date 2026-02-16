# UR-07: Active Admin Role

## Overview

| Property | Value |
|----------|-------|
| **ID** | UR-07 |
| **Name** | Active Admin Role |
| **Points** | +2 |
| **Type** | Risk Indicator |
| **Module** | `ioc-userrisk-adminrole.ps1` |

## Description

Detects when the user has administrative privileges in the Microsoft 365 tenant. Admin accounts require heightened security scrutiny.

## Why This Matters

Admin accounts:
- Have elevated privileges
- Can access all organizational data
- Can modify security settings
- Are high-value targets for attackers
- Require additional protection

## Detection Logic

```powershell
# Get directory role assignments for user
$assignments = Get-MgRoleManagementDirectoryRoleAssignment `
    -Filter "principalId eq '$($UserObject.Id)'" -All

if ($assignments.Count -gt 0) {
    # Get role names for display
    $directoryRoles = foreach ($assignment in $assignments) {
        $role = Get-MgRoleManagementDirectoryRoleDefinition `
            -UnifiedRoleDefinitionId $assignment.RoleDefinitionId
        [PSCustomObject]@{ RoleName = $role.DisplayName }
    }
    $score = 2
}
```

## Data Source

- **API**: Microsoft Graph Directory Roles
- **Endpoint**: `Get-MgRoleManagementDirectoryRoleAssignment`
- **Filter**: User's principalId

## Common Admin Roles

| Role | Risk Level |
|------|------------|
| Global Administrator | Critical |
| Privileged Role Administrator | Critical |
| Security Administrator | High |
| Exchange Administrator | High |
| SharePoint Administrator | Medium |
| User Administrator | Medium |

## Example Scenarios

### Triggered (+2 points)
- User is Global Administrator
- User has Security Reader role
- User is Exchange Administrator

### Not Triggered (0 points)
- Standard user with no admin roles
- User with only end-user permissions

## Context Considerations

This indicator:
- Is informational, not necessarily negative
- Increases impact if account is compromised
- Should trigger extra scrutiny of other indicators
- May require stricter security response

## Recommended Actions

1. Verify admin role is appropriate
2. Ensure privileged access policies apply
3. Consider PIM (Privileged Identity Management)
4. Review if role is still needed
5. Apply break-glass account procedures if compromised

## Related Indicators

- UR-01: No MFA Registered (critical for admins)
- UR-10: CA Protection

## Configuration

```json
// config/settings.json
"UR-07": {
    "name": "Active Admin Role",
    "points": 2,
    "description": "User has elevated administrative privileges"
}
```
