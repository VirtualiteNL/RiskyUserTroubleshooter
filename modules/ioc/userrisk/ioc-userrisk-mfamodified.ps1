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
function Get-RecentMfaChanges {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)][string]$UPN
    )

    Write-Host "🔍 Checking recent MFA changes for $UPN..." -ForegroundColor Cyan

    try {
        # 📥 Fetch all audit log entries for the user
        $adminChanges = Get-MgAuditLogDirectoryAudit -Filter "targetResources/any(t:t/userPrincipalName eq '$UPN')" -All

        # 🕓 Filter for recent MFA method changes within the last 7 days
        # Match various MFA-related activity names:
        # - "Authentication Method" (e.g., "User has registered all required authentication methods")
        # - "security info" (e.g., "User registered security info", "Admin deleted security info")
        # - "Authenticator" (e.g., "User registered Authenticator App")
        # - "StrongAuthentication" (e.g., updates via Azure MFA StrongAuthenticationService)
        $recentMfaChanges = $adminChanges | Where-Object {
            ($_.ActivityDisplayName -match "Authentication Method|security info|Authenticator|StrongAuthentication" -or
             $_.Category -eq "Authentication Methods") -and
            $_.ActivityDateTime -gt (Get-Date).AddDays(-7)
        }

        Write-Host "✅ Found $($recentMfaChanges.Count) recent MFA changes for $UPN" -ForegroundColor Green
        Write-Log -Type "Information" -Message "✅ Retrieved $($recentMfaChanges.Count) recent MFA changes for $UPN"
        return $recentMfaChanges
    }
    catch {
        Write-Host "❌ Failed to retrieve recent MFA changes for $UPN" -ForegroundColor Red
        Write-Log -Type "Error" -Message "❌ Failed to retrieve recent MFA changes for ${UPN}: $($_.Exception.Message)"
        return @()
    }
}
