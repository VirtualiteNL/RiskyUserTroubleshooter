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
function Test-SignInAbuseAsnRisk {
    <#
    .SYNOPSIS
        Evaluates Sign-In IOCs for foreign IP and suspicious ASN (SR-05, SR-06)
    .DESCRIPTION
        Checks sign-in events against AbuseIPDB scores and ASN reputation.
        Points are synchronized with config/settings.json iocDefinitions.signInRisk
    #>
    param (
        [Parameter(Mandatory = $true)]
        [object]$SignIn,

        [Parameter(Mandatory = $true)]
        [string]$UPN
    )

    # 🌍 Initialize score values
    $countryScore = 0
    $asnScore = 0

    # 🛰️ Extract and normalize AbuseIPDB score
    $abuseNotAvailable = ($null -eq $SignIn.AbuseScore -or $SignIn.AbuseScore -eq "N/A" -or -not ($SignIn.AbuseScore -match '\d+'))
    if ($abuseNotAvailable) {
        [int]$abuseVal = 0
        Write-Log -Type "Information" -Message "ℹ️ No AbuseIPDB score available for IP $($SignIn.IpAddress) – Risk +0"
    } else {
        [int]$abuseVal = [int]($SignIn.AbuseScore -replace '[^\d]', '')
    }


    # 📍 Determine if location is foreign (non-NL)
    $isForeign = $SignIn.Location.CountryOrRegion -and
                 $SignIn.Location.CountryOrRegion -notin @("NL", "Netherlands")

    # 🌐 SR-05: Foreign IP - score based on AbuseIPDB reputation
    # Points: 1-3 depending on abuse score (per settings.json)
    if ($isForeign) {
        if ($abuseVal -lt 10)       { $countryScore = 1 }
        elseif ($abuseVal -lt 26)   { $countryScore = 1 }
        elseif ($abuseVal -lt 50)   { $countryScore = 2 }
        else                        { $countryScore = 3 }

        Write-Log -Type "Alert" -Message "SR-05: Foreign IP ($($SignIn.Location.CountryOrRegion)) with AbuseScore $abuseVal – Risk +$countryScore"
    }

    # 🛰️ Check if ASN is in trusted Dutch ISP whitelist
    $trustedASNs = @("ziggo", "kpn", "t-mobile", "xs4all", "vodafone", "tele2", "chello", "solcon", "caiway", "delta")
    $asn = $SignIn.ASN

    $asnIsUntrusted = $asn -and ($trustedASNs -notcontains ($asn.ToLower()))

    # 🚨 SR-06: Suspicious IP+ASN - high abuse score combined with unknown ASN
    # Points: 3 (per settings.json)
    if ($abuseVal -ge 70 -and $asnIsUntrusted) {
        $asnScore = 3
        Write-Log -Type "Alert" -Message "SR-06: Suspicious IP $($SignIn.IpAddress) – AbuseScore $abuseVal + Unknown ASN '$asn' – Risk +3"
    }

    # 🧾 Return both breakdown entries (even if 0)
    $abuseDisplay = if ($abuseNotAvailable) { "N/A" } else { $abuseVal }
    return @(
        @{
            Name   = "Foreign IP + AbuseIPDB score ($abuseDisplay)"
            Points = $countryScore
        },
        @{
            Name   = "Suspicious IP (AbuseIPDB + ASN)"
            Points = $asnScore
        }
    )
}