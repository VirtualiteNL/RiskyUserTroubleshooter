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
    if ($null -eq $SignIn.AbuseScore -or -not ($SignIn.AbuseScore -match '\d+')) {
        [int]$abuseVal = 0
        Write-Log -Type "Information" -Message "ℹ️ No AbuseIPDB score available for IP $($SignIn.IpAddress) – Risk +0"
    } else {
        [int]$abuseVal = [int]($SignIn.AbuseScore -replace '[^\d]', '')
    }


    # 📍 Determine if location is foreign (non-NL)
    $isForeign = $SignIn.Location.CountryOrRegion -and
                 $SignIn.Location.CountryOrRegion -notin @("NL", "Netherlands")

    if ($isForeign) {
        # ⚖️ Assign score based on AbuseIPDB reputation
        if ($abuseVal -lt 10)       { $countryScore = 0.5 }
        elseif ($abuseVal -lt 26)   { $countryScore = 1 }
        elseif ($abuseVal -lt 50)   { $countryScore = 2 }
        else                        { $countryScore = 3 }

        Write-Log -Type "Alert" -Message "IOC 2: Foreign IP ($($SignIn.Location.CountryOrRegion)) with AbuseScore $abuseVal – Risk +$countryScore"
    }

    # 🛰️ Check if ASN is in trusted Dutch ISP whitelist
    $trustedASNs = @("ziggo", "kpn", "t-mobile", "xs4all", "vodafone", "tele2", "chello", "solcon", "caiway", "delta")
    $asn = $SignIn.ASN

    $asnIsUntrusted = $asn -and ($trustedASNs -notcontains ($asn.ToLower()))

    # 🚨 Check for high AbuseIPDB score combined with unknown ASN
    if ($abuseVal -ge 70 -and $asnIsUntrusted) {
        $asnScore = 2
        Write-Log -Type "Alert" -Message "IOC 9: Suspicious IP $($SignIn.IpAddress) – AbuseScore $abuseVal + Unknown ASN '$asn' – Risk +2"
    }

    # 🧾 Return both breakdown entries (even if 0)
    return @(
        @{
            Name   = "Foreign IP + AbuseIPDB score ($abuseVal)"
            Points = $countryScore
        },
        @{
            Name   = "Suspicious IP (AbuseIPDB + ASN)"
            Points = $asnScore
        }
    )
}