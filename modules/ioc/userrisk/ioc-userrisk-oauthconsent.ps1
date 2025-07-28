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
function Get-UserOauthConsents {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)][string]$UserId
    )

    try {
        $grants = Get-MgUserOauth2PermissionGrant -UserId $UserId -ErrorAction Stop
        Write-Host "🔑 Retrieved $($grants.Count) OAuth consents for user: $UserId" -ForegroundColor Gray
        Write-Log -Type "Information" -Message "✅ Retrieved $($grants.Count) OAuth consents for user $UserId"
        return $grants
    } catch {
        Write-Host "❌ Failed to retrieve OAuth consents for $UserId" -ForegroundColor Red
        Write-Log -Type "Error" -Message "❌ Failed to retrieve OAuth consents for user ${UserId}: $_"
        return @()
    }
}
