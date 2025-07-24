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
function Test-SignInMfaFailure {
    param (
        [Parameter(Mandatory = $true)]
        $SignIn,

        [Parameter(Mandatory = $true)]
        [string]$UPN
    )

    $mfaFailure = (
        $SignIn.Status.ErrorCode -eq 500121 -or
        $SignIn.Status.ErrorCode -eq 50074  -or
        $SignIn.Status.FailureReason -like "*multifactor*" -or
        $SignIn.Status.AdditionalDetails -eq "interrupted"
    )

    if ($mfaFailure) {
        Write-Log -Type "Alert" -Message "Sign-in failed at MFA stage after valid credentials were entered for $($SignIn.IpAddress) (User: $UPN)"
        return 1
    }

    return 0
}