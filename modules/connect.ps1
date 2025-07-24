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
    # These scopes provide access to logs, users, policies, auth methods, and risk data.
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
        # 📡 Connect to Microsoft Graph silently using delegated scopes
        Connect-MgGraph -Scopes $scopes -NoWelcome | Out-Null
        Write-Log -Type "Information" -Message "Connected to Microsoft Graph with required scopes."

        # ✉️ Connect to Exchange Online for mailbox analysis and forwarding rules
        Connect-ExchangeOnline -ShowBanner:$false | Out-Null
        Write-Log -Type "Information" -Message "Connected to Exchange Online PowerShell session."
    } catch {
        # ❌ Log and escalate any authentication errors
        Write-Log -Type "Error" -Message "Failed to connect to Graph or Exchange: $_"
        throw "❌ Connection to Microsoft Graph or Exchange Online failed: $_"
    }
}