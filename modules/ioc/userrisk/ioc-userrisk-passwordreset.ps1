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
#>function Get-UserPasswordResetEvents {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string]$UPN,

        [int]$LookBackDays = 30
    )

    # 🗓️ Calculate filter date
    $since = (Get-Date).AddDays(-$LookBackDays)

    # ✅ Ensure audit log is present
    if (-not $global:UserDirectoryAuditLogs) {
        Write-Host "❌ Audit log not found for $UPN" -ForegroundColor Red
        Write-Log -Type "Error" -Message "❌ Audit log not found in scope for ${UPN}"
        return @()
    }

    # 🔍 Filter audit events for password reset / change
    $pwdEvents = $global:UserDirectoryAuditLogs |
        Where-Object {
            ($_.activityDisplayName -in @(
                'Reset user password',
                'Change user password'
            )) -and
            ($_.targetResources[0].userPrincipalName -eq $UPN) -and
            ([datetime]$_.activityDateTime -ge $since)
        }

    # 📝 Log result with dynamic type
    $logType = if ($pwdEvents.Count -gt 0) { "Alert" } else { "OK" }
    Write-Host "🔑 Password reset/change events for ${UPN}: $($pwdEvents.Count)" -ForegroundColor Gray
    Write-Log -Type $logType -Message "🔑 Password reset/change events found for ${UPN}: $($pwdEvents.Count)"

    return $pwdEvents
}