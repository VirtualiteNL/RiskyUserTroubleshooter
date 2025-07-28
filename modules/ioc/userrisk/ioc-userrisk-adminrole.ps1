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

function Get-UserAdminRoles {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)][string]$UserId
    )

    $directoryRoles = @()

    try {
        Write-Host "📥 Retrieving activated directory roles..." -ForegroundColor Cyan
        # 📜 Retrieve every activated directory role in the tenant
        $allRoles = Get-MgDirectoryRole -All
        Write-Log -Type "Information" -Message "📥 Retrieved directory roles for tenant."
    }
    catch {
        Write-Host "❌ Failed to retrieve directory roles." -ForegroundColor Red
        Write-Log -Type "Error" -Message "❌ Failed to retrieve directory roles: $($_.Exception.Message)"
        return $directoryRoles    # return empty on error
    }

    foreach ($role in $allRoles) {
        try {
            Write-Host "🔎 Checking members of role: $($role.DisplayName)" -ForegroundColor Gray
            # 👥 Enumerate members of the current role
            $members = Get-MgDirectoryRoleMember -DirectoryRoleId $role.Id -ErrorAction Stop
            foreach ($member in $members) {
                if ($member.Id -eq $UserId) {
                    $directoryRoles += [PSCustomObject]@{
                        RoleName = $role.DisplayName
                        RoleId   = $role.Id
                    }

                    # 📝 Log the matched role
                    Write-Host "⚠️ User is a member of privileged role: $($role.DisplayName)" -ForegroundColor Yellow
                    Write-Log -Type "Alert" -Message "⚠️ User is a member of privileged role: $($role.DisplayName)"
                    break  # no need to scan further members for this role
                }
            }
        }
        catch {
            Write-Host "⚠️ Failed to retrieve members for role: $($role.DisplayName)" -ForegroundColor DarkYellow
            Write-Log -Type "Error" -Message "⚠️ Failed to retrieve members for role $($role.DisplayName): $($_.Exception.Message)"
            continue
        }
    }

    return $directoryRoles
}
