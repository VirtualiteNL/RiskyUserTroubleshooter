<#
.SYNOPSIS
    📊 Microsoft 365 Risky User Troubleshooter

.DESCRIPTION
    This script connects to Microsoft 365 (via Graph API and Exchange Online),
    collects data on a risky user. The output is a Fluent UI-style HTML dashboard
    with popups, summaries, and optional AI-generated advisory.

.AUTHOR
    👤 Danny Vorst (@Virtualite.nl)
    💼 https://virtualite.nl | 🔗 https://github.com/VirtualiteNL

.LICENSE
    🔐 Microsoft 365 Risky User Troubleshooter – Copyright & License

    This script is developed and maintained by Danny Vorst (Virtualite.nl).
    It is licensed for **non-commercial use only**.

    🟢 Allowed:
    - Free to use internally for reporting, monitoring, or educational purposes
    - Forks or modifications are allowed **only if published publicly** (e.g., on GitHub)
    - Author name, styling, logo and script headers must remain unchanged

    🔴 Not allowed:
    - Commercial use, resale, or integration in closed-source tooling
    - Removing Virtualite branding, layout, or author headers

    ⚠️ By using this script, you agree to the license terms.
    Violations may result in takedown notices, DMCA reports, or legal action.

    ℹ️ Also licensed under Creative Commons BY-NC-SA 4.0 where compatible.
    See LICENSE.md for full terms.
#>

function Get-UserCaProtectionStatus {
    param (
        [string]$UPN,
        [object]$UserObject
    )

    try {
        Write-Host "🔍 Starting Conditional Access evaluation for: $UPN" -ForegroundColor Cyan
        Write-Log -Type "Information" -Message "🔍 Starting Conditional Access evaluation for: $UPN"

        # 🌐 Retrieve all Conditional Access policies
        Write-Host "🌐 Retrieving Conditional Access policies..." -ForegroundColor Gray
        $uri = "https://graph.microsoft.com/beta/identity/conditionalAccess/policies"
        $response = Invoke-MgGraphRequest -Method GET -Uri $uri
        if (-not $response -or -not $response.value) {
            Write-Log -Type "Error" -Message "❌ CA response missing or invalid."
            throw "CA response invalid"
        }

        $allPolicies = $response.value
        Write-Log -Type "Information" -Message "📥 Loaded $($allPolicies.Count) Conditional Access policies"

        # 🎯 Filter only enabled policies
        $enabledPolicies = $allPolicies | Where-Object { $_.state -eq "enabled" }
        Write-Host "🎯 Filtering enabled CA policies..." -ForegroundColor Gray
        Write-Log -Type "Information" -Message "📥 Loaded $($enabledPolicies.Count) enabled Conditional Access policies"

        # 🔐 Filter for policies that enforce protection (MFA/device/compliant)
        Write-Host "🔐 Filtering protective policies (MFA, compliantDevice, domainJoin)..." -ForegroundColor Gray
        $protectivePolicies = $enabledPolicies | Where-Object {
            $_.grantControls.builtInControls -contains "mfa" -or
            $_.grantControls.builtInControls -contains "compliantDevice" -or
            $_.grantControls.builtInControls -contains "domainJoinedDevice" -or
            $_.grantControls.authenticationStrength -ne $null
        }
        Write-Log -Type "Information" -Message "🔐 Found $($protectivePolicies.Count) protective CA policies"

        # 🎓 Retrieve user roles if not already cached
        if (-not $global:userRoles) { $global:userRoles = @{} }
        if (-not $global:userRoles.ContainsKey($UPN)) {
            Write-Host "🎓 Retrieving user role assignments..." -ForegroundColor Gray
            try {
                $assignments = Get-MgRoleManagementDirectoryRoleAssignment -Filter "principalId eq '$($UserObject.Id)'" -All
                $roleIds = $assignments | ForEach-Object { $_.RoleDefinitionId }
                $global:userRoles[$UPN] = $roleIds
                Write-Log -Type "Information" -Message "🎓 Found $($roleIds.Count) roles for $UPN"
            } catch {
                $global:userRoles[$UPN] = @()
                Write-Log -Type "Error" -Message "❌ Failed to retrieve roles: $($_.Exception.Message)"
            }
        }

        $userProtected = $false
        $appliesToAllApps = $false
        $userGroups = @()

        foreach ($policy in $enabledPolicies) {
            $policyName = $policy.displayName
            $users = $policy.conditions.users

            if (-not $users) {
                Write-Log -Type "Information" -Message "⏭️ Skipping policy ($policyName): no user condition"
                continue
            }

            $includeUsers  = @($users.includeUsers)
            $excludeUsers  = @($users.excludeUsers)
            $includeGroups = @($users.includeGroups)
            $excludeGroups = @($users.excludeGroups)
            $includeRoles  = @($users.includeRoles)
            $excludeRoles  = @($users.excludeRoles)

            $apps = $policy.conditions.applications
            $allAppsCovered = $false
            $appsExcluded = $false
            if ($apps) {
                $allAppsCovered = (
                    ($apps.includeApplications -is [array] -and $apps.includeApplications -contains "All") -or
                    ($apps.includeApplications.'@odata.type' -eq "#microsoft.graph.allApplications")
                )
                $appsExcluded = ($apps.excludeApplications -and $apps.excludeApplications.Count -gt 0)
            }

            # 👥 Retrieve user groups once if needed
            if ($userGroups.Count -eq 0 -and ($includeGroups.Count -gt 0 -or $excludeGroups.Count -gt 0)) {
                Write-Host "👥 Retrieving user group memberships..." -ForegroundColor Gray
                $userGroups = (Get-MgUserMemberOf -UserId $UPN -All | Where-Object { $_.'@odata.type' -eq "#microsoft.graph.group" }).Id
            }

            $userRoleIds = $global:userRoles[$UPN]

            $includedUPN     = ($includeUsers -contains $UserObject.Id -or $includeUsers -contains "All")
            $includedGroup   = ($includeGroups | Where-Object { $userGroups -contains $_ }).Count -gt 0
            $includedRole    = ($includeRoles | Where-Object { $userRoleIds -contains $_ }).Count -gt 0
            $excludedUPN     = ($excludeUsers -contains $UserObject.Id)
            $excludedGroup   = ($excludeGroups | Where-Object { $userGroups -contains $_ }).Count -gt 0
            $excludedRole    = ($excludeRoles | Where-Object { $userRoleIds -contains $_ }).Count -gt 0

            # ⛔ Skip policy if user is not included
            if (-not ($includedUPN -or $includedGroup -or $includedRole)) {
                Write-Log -Type "Information" -Message "⏭️ Skipping policy ($policyName): user not included"
                continue
            }

            # ⛔ Skip if not a protective policy
            $isProtective = $protectivePolicies -contains $policy
            if (-not $isProtective) {
                Write-Log -Type "Information" -Message "⏭️ Skipping policy ($policyName): does not enforce MFA/device/auth strength"
                continue
            }

            # 🧾 Log everything
            $logSummary = "💡 {$policyName}: IncludedUPN=$includedUPN, IncludedGroup=$includedGroup, IncludedRole=$includedRole, " +
                          "ExcludedUPN=$excludedUPN, ExcludedGroup=$excludedGroup, ExcludedRole=$excludedRole, " +
                          "AllApps=$allAppsCovered, AppExcluded=$appsExcluded"
            Write-Log -Type "Information" -Message $logSummary

            # ⛔ Skip if excluded anywhere
            if ($excludedUPN -or $excludedGroup -or $excludedRole) {
                Write-Log -Type "Information" -Message "⛔ $UPN is excluded in $policyName → not protected"
                continue
            }

            # ✅ Protection applies
            $userProtected = $true
            if ($allAppsCovered -and -not $appsExcluded) {
                $appliesToAllApps = $true
            }
            Write-Log -Type "Information" -Message "✅ $UPN is protected by policy: $policyName"
        }

        # 🧠 Add final human-readable outcome
        if (-not $global:aiadvisory.UserRisk) { $global:aiadvisory.UserRisk = @{} }

        if ($userProtected) {
            if (-not $appliesToAllApps -or $appsExcluded) {
                $global:aiadvisory.UserRisk.CAProtection = "⚠️ Protected by Conditional Access, but not for all apps"
                Write-Log -Type "Alert" -Message "⚠️ $UPN protected by CA, but not all apps covered or some apps excluded"
                return @{ Name = "CA protection"; Condition = $true; Points = 2; MaxPoints = 3 }
            } else {
                $global:aiadvisory.UserRisk.CAProtection = "✅ Fully protected by Conditional Access"
                Write-Log -Type "OK" -Message "✅ $UPN protected by CA for all apps"
                return @{ Name = "CA protection"; Condition = $false; Points = 0; MaxPoints = 3 }
            }
        } else {
            $global:aiadvisory.UserRisk.CAProtection = "🚫 Not protected by any Conditional Access policy"
            Write-Log -Type "Alert" -Message "🚫 $UPN not protected by any MFA/device CA policy"
            return @{ Name = "CA protection"; Condition = $true; Points = 3; MaxPoints = 3 }
        }
    }
    catch {
        $global:aiadvisory.UserRisk.CAProtection = "❌ Error during CA evaluation"
        Write-Log -Type "Error" -Message "❌ CA check failed for ${UPN}: $($_.Exception.Message)"
        return @{ Name = "CA protection"; Condition = $true; Points = 1 }
    }
}
