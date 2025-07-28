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

function Get-AppCategory {
    param([string]$AppName)

    # 🧠 Categorize application name into one of several app types
    switch -Regex ($AppName) {
        # 🔐 Core authentication services used by Microsoft 365
        "Authentication Broker|Exchange REST API|Office365 Shell" {
            return "Core Auth"
        }

        # 🧩 Microsoft 365 productivity apps
        "Teams|Outlook|Word|Excel|Office" {
            return "M365 App"
        }

        # 🧪 Script-based access, often via Graph API or PowerShell
        "Graph|PowerShell" {
            return "Script"
        }

        # 👤 User-facing portals and account profile components
        "My Signins|My Profile|OfficeHome|Microsoft Account Controls|Microsoft Account Controls V2" {
            return "User Portal"
        }

        # 🔁 Fallback: return original name if no category matched
        default {
            return $AppName
        }
    }
}