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
function Test-NewUserAccount {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)][string]$UPN,
        [Parameter(Mandatory)][datetime]$CreatedDate
    )

    try {
        $accountAgeDays = (New-TimeSpan -Start $CreatedDate -End (Get-Date)).Days
        Write-Host "📆 Account created on: $CreatedDate ($accountAgeDays days ago)" -ForegroundColor Gray
        Write-Log -Type "Information" -Message "📆 Account creation date: $CreatedDate — Age in days: $accountAgeDays"

        if ($accountAgeDays -lt 7) {
            Write-Host "⚠️ User account is NEW (younger than 7 days): $UPN" -ForegroundColor Yellow
            Write-Log -Type "Alert" -Message "🧾 UserRisk IOC 8 triggered – Account is younger than 7 days (${accountAgeDays} days): ${UPN}"
            return $true
        } else {
            Write-Host "✅ Account is older than 7 days: $UPN" -ForegroundColor Green
            Write-Log -Type "OK" -Message "✅ Account is older than 7 days (${accountAgeDays} days): ${UPN}"
            return $false
        }
    }
    catch {
        Write-Host "❌ Failed to check account age for $UPN" -ForegroundColor Red
        Write-Log -Type "Error" -Message "❌ Failed to evaluate account age for ${UPN}: $($_.Exception.Message)"
        return $null
    }
}
