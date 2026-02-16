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

function Test-SignInBaselineIOCs {
    <#
    .SYNOPSIS
        Evaluates baseline Sign-In IOCs (SR-01, SR-07, SR-08, SR-13, SR-14, SR-15)
    .DESCRIPTION
        Checks sign-in events against baseline indicators of compromise.
        Points are synchronized with config/settings.json iocDefinitions.signInRisk
    #>
    param (
        [Parameter(Mandatory)]
        $SignIn,

        [Parameter(Mandatory)]
        [hashtable]$WorkingHours  # expected keys: Start, End
    )

    $results = @()

    try {
        # 📡 SR-01: Legacy protocol usage (IMAP/POP/SMTP - no MFA possible)
        # Points: 3 (per settings.json)
        $score = if ($SignIn.ClientAppUsed -match 'imap|pop|smtp|other|unknown') { 3 } else { 0 }
        $results += @{ Name = "Legacy protocol (IMAP/POP/SMTP)"; Points = $score }
    }
    catch {
        Write-Log -Type "Error" -Message "❌ Failed to evaluate ClientAppUsed for ${SignIn.IpAddress}: $($_.Exception.Message)"
    }

    try {
        # ✅ SR-13: Trusted Device (Azure AD joined) - safety indicator
        # Points: -2 (per settings.json)
        $score = if ($SignIn.DeviceDetail.TrustType -eq "Azure AD joined") { -2 } else { 0 }
        $results += @{ Name = "Trusted device (AzureAD joined)"; Points = $score }
    }
    catch {
        Write-Log -Type "Error" -Message "❌ Failed to evaluate trust type for ${SignIn.IpAddress}: $($_.Exception.Message)"
    }

    try {
        # 🛡️ SR-14: Compliant Device (Intune compliant) - safety indicator
        # Points: -3 (per settings.json)
        $score = if ($SignIn.DeviceDetail.IsCompliant -eq $true) { -3 } else { 0 }
        $results += @{ Name = "Compliant device"; Points = $score }
    }
    catch {
        Write-Log -Type "Error" -Message "❌ Failed to evaluate compliance status for ${SignIn.IpAddress}: $($_.Exception.Message)"
    }

    try {
        # 🇳🇱 SR-15: Location: Netherlands - sign-in from expected location
        # Points: -1 (per settings.json)
        $score = if ($SignIn.Location.CountryOrRegion -in @("NL", "Netherlands")) { -1 } else { 0 }
        $results += @{ Name = "Location: Netherlands"; Points = $score }
    }
    catch {
        Write-Log -Type "Error" -Message "❌ Failed to evaluate location for ${SignIn.IpAddress}: $($_.Exception.Message)"
    }

    try {
        # ⏰ SR-08: Login outside inferred working hours
        # Points: 1 (per settings.json)
        $hour = ([datetime]$SignIn.CreatedDateTime).ToLocalTime().Hour
        $score = if ($hour -lt ($WorkingHours.Start - 2) -or $hour -gt ($WorkingHours.End + 2)) { 1 } else { 0 }
        $results += @{ Name = "Login outside working hours ($($WorkingHours.Start):00–$($WorkingHours.End):00)"; Points = $score }
    }
    catch {
        Write-Log -Type "Error" -Message "❌ Failed to evaluate working hours for ${SignIn.IpAddress}: $($_.Exception.Message)"
    }

    try {
        # ✈️ SR-07: Impossible travel detection
        # Points: 4 (per settings.json)
        $score = if ($SignIn.ImpossibleTravelDetected) { 4 } else { 0 }
        $results += @{ Name = "Impossible travel between sign-ins"; Points = $score }
    }
    catch {
        Write-Log -Type "Error" -Message "❌ Failed to read ImpossibleTravelDetected for ${SignIn.IpAddress}: $($_.Exception.Message)"
    }

    return $results
}
