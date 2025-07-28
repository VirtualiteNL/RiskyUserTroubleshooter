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
function Get-UserWorkingHoursRange {
    param (
        [Parameter(Mandatory = $true)]
        [array]$SignIns
    )

    Write-Log -Type "Information" -Message "📊 Calculating working hours range based on sign-in history..."

    # ⏱️ Extract the hour from each sign-in timestamp
    $hours = $SignIns | ForEach-Object {
        ([datetime]$_.CreatedDateTime).ToLocalTime().Hour
    }

    # ⛔ Fallback to default if not enough sign-ins
    if ($hours.Count -lt 8) {
        Write-Log -Type "OK" -Message "⚠️ Less than 8 sign-ins found – using default working hours: 08:00–17:00"
        return @{ Start = 8; End = 17 }
    }

    # 🧮 Group sign-ins by hour to find the most active hours
    $grouped = $hours | Group-Object | Sort-Object Count -Descending
    $topHours = $grouped | Select-Object -First 8 | ForEach-Object { [int]$_.Name }

    if ($topHours.Count -eq 0) {
        Write-Log -Type "OK" -Message "⚠️ No valid sign-in hours found – using default working hours: 08:00–17:00"
        return @{ Start = 8; End = 17 }
    }

    $startHour = ($topHours | Measure-Object -Minimum).Minimum
    $endHour   = ($topHours | Measure-Object -Maximum).Maximum + 1

    if ($null -eq $startHour -or $null -eq $endHour) {
        Write-Log -Type "OK" -Message "⚠️ Unable to infer working hours – using default: 08:00–17:00"
        return @{ Start = 8; End = 17 }
    }

if ($null -ne $startHour -and $null -ne $endHour) {
    Write-Log -Type "OK" -Message "🕘 Inferred working hours range: $startHour:00–$endHour:00"
} else {
    Write-Log -Type "OK" -Message "⚠️ Inferred working hours not available – default used: 08:00–17:00"
}
    return @{ Start = $startHour; End = $endHour }
}
