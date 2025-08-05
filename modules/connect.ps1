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
function Connect-GraphAndExchange {
    # 🔐 Define the required Microsoft Graph scopes
    $scopes = @(
        "AuditLog.Read.All",
        "User.Read.All",
        "Directory.Read.All",
        "Mail.Read",
        "MailboxSettings.Read",
        "Policy.Read.All",
        "UserAuthenticationMethod.Read.All",
        "IdentityRiskyUser.Read.All"
    )

    try {
        # 📡 Connect to Microsoft Graph
        Write-Host "🌐 Connecting to Microsoft Graph..." -ForegroundColor Cyan
        Connect-MgGraph -Scopes $scopes -NoWelcome | Out-Null

        # ✉️ Connect to Exchange Online
        Write-Host "📬 Connecting to Exchange Online..." -ForegroundColor Cyan
        Connect-ExchangeOnline -ShowBanner:$false | Out-Null
        Write-Host "🔗 All services connected successfully." -ForegroundColor Green
    } catch {
        # ❌ Handle authentication failure
        Write-Host "❌ Connection to Microsoft 365 failed." -ForegroundColor Red
        Write-Log -Type "Error" -Message "❌ Connection failed: $($_.Exception.Message)"
        throw "❌ Connection to Microsoft Graph or Exchange Online failed: $($_.Exception.Message)"
    }
}