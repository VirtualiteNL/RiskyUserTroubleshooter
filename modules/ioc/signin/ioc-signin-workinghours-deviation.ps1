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
function Test-SignInOutsideWorkingHours {
    param (
        [Parameter(Mandatory = $true)]
        [array]$SignIns,

        [Parameter(Mandatory = $true)]
        [hashtable]$WorkingHours,

        [Parameter(Mandatory = $true)]
        [string]$UPN
    )

    Write-Log -Type "Information" -Message "⏰ Checking for sign-ins outside working hour window..."

    $deviantSignIns = @()

    foreach ($s in $SignIns) {
        $loginHour = ([datetime]$s.CreatedDateTime).ToLocalTime().Hour
        if ($loginHour -lt ($WorkingHours.Start - 2) -or
            $loginHour -gt ($WorkingHours.End + 2)) {
            $deviantSignIns += $s
        }
    }

    if ($deviantSignIns.Count -gt 0) {
        Write-Log -Type "Alert" -Message "$($deviantSignIns.Count) sign-ins for $UPN detected outside normal hours ($($WorkingHours.Start):00–$($WorkingHours.End):00)"
    } else {
        Write-Log -Type "OK" -Message "No logins outside normal working pattern ($($WorkingHours.Start):00–$($WorkingHours.End):00)"
    }

    return $deviantSignIns
}
