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
    # 🧠 Load application categorization helper (used for clustering & IOC analysis)
    . "$PSScriptRoot\..\modules\ioc\signin\ioc-signin-appcategory.ps1"

function Get-SignInRiskSection {
    param (
        [string]$LogPath,
        [string]$UPN
    )

    # 📦 Initialize popup container and risk list
    $htmlPopups = ""
    $riskySignIns = @()

    # 📅 Filter sign-ins to only include the last 30 days
    $dateFilter = (Get-Date).AddDays(-30).ToString("yyyy-MM-ddTHH:mm:ssZ")

    # 📄 Retrieve full user object from Microsoft Graph using UPN
    $user = Get-MgUser -UserId $UPN -ErrorAction SilentlyContinue
    if (-not $user) {
        Write-Log -Type "Error" -Message "User not found: $UPN"
        return "<h2>Sign-In Risk Overview</h2><p>User not found.</p>"
    }

    # 📥 Query interactive sign-ins for the user within the date range
    $signins = Get-MgAuditLogSignIn -Filter "userId eq '$($user.Id)' and createdDateTime ge $dateFilter" -All
    if (-not $signins) {
        Write-Log -Type "OK" -Message "No sign-ins for $UPN"
        return "<h2>Sign-In Risk Overview</h2><p>No sign-ins found for this user.</p>"
    }

    # 🧮 Extract and initialize AbuseIPDB scores for all unique IPs
    $allIps = $signins | ForEach-Object { $_.IpAddress } | Where-Object { $_ }
    Initialize-AbuseIpScores -IpAddresses $allIps

    # 🧾 Log number of sign-ins retrieved for this user
    Write-Log -Type "Information" -Message "Sign-ins found: $($signins.Count)"

        # 🔍 Load session anomaly module (adds flags to $signins)
    . "$PSScriptRoot\sessions.ps1"
    Test-SignInSessionAnomalies -SignIns $signins

    # 🧭 Load impossible travel detection module
    . "$PSScriptRoot\..\modules\ioc\signin\ioc-signin-impossibletravel.ps1"
    # ➡️ Flag impossible travel detections (modifies $signins inline)
    $signins = Test-ImpossibleTravel -SignIns ($signins | Sort-Object CreatedDateTime)

    # 🕒 Define or infer user's typical working hours for anomaly detection
    . "$PSScriptRoot\..\modules\ioc\signin\ioc-signin-workinghours.ps1"
    # 🕘 Get user's inferred working hour range based on recent activity
    if ($null -ne $signins -and $signins.Count -gt 0) {
        $riskWorkingHours = Get-UserWorkingHoursRange -SignIns $signins
    } else {
        Write-Log -Type "Error" -Message "❌ Fatal error: No sign-in data found to calculate working hours."
        $riskWorkingHours = @{ Start = 8; End = 17 } # ⛔ Default fallback
}

    # 🔗 Group similar sign-ins into logical clusters based on IP, app, location and timing
    . "$PSScriptRoot\..\modules\ioc\signin\ioc-signin-clustering.ps1"

    # 🚨 Detect sign-ins that deviate from the user’s usual working pattern
    $deviantSignIns = @()

    # ⏰ Load deviation detector for sign-ins outside working hours
    . "$PSScriptRoot\..\modules\ioc\signin\ioc-signin-workinghours-deviation.ps1"
    # 🚨 Detect sign-ins that deviate from the user’s usual working pattern
    $deviantSignIns = Test-SignInOutsideWorkingHours -SignIns $signins -WorkingHours $riskWorkingHours -UPN $UPN

    # 🔗 Check if the sign-in is from a foreign IP and calculate AbuseIPDB score
. "$PSScriptRoot\..\modules\ioc\signin\ioc-signin-abuseasn.ps1"
    # 📊 Start the per-sign-in risk scoring and enrichment process
    foreach ($s in $signins) {
        $popupId   = "popup-" + ([guid]::NewGuid().ToString())
        $ip        = $s.IpAddress
        $score     = 0
        $breakdown = @()

    # 🌐 Query AbuseIPDB to retrieve risk score for IP
    if ($ip) {
        $abuseScore = Get-AbuseIpScore -IpAddress $ip
        $s | Add-Member -NotePropertyName AbuseScore -NotePropertyValue $abuseScore -Force
    }

    # 🔐 Load MFA failure detector module
    . "$PSScriptRoot\..\modules\ioc\signin\ioc-signin-mfafailure.ps1"
    $mfaFailScore = Test-SignInMfaFailure -SignIn $s -UPN $UPN
    
    # 🧮 Load baseline IOCs to compute individual IOC contributions to the risk score
    . "$PSScriptRoot\..\modules\ioc\signin\ioc-signin-baselineiocs.ps1"

    # 📊 Define the maximum theoretical IOC score model (only positive scoring IOCs are counted)
    $possibleIocs = @(
        @{ Name = "Sign-in failed at MFA stage after valid credentials were entered"; Points = 1 },   # 🔐 MFA challenge failed
        @{ Name = "Legacy protocol (IMAP/POP/SMTP)"; Points = 2 }, # 📡 Legacy protocol usage
        @{ Name = "Foreign IP + AbuseIPDB score"; Points = 3 }, # 🌍 Risky foreign IP
        @{ Name = "No MFA used"; Points = 1 }, # ❌ MFA missing
        @{ Name = "Conditional Access failure"; Points = 2 }, # 🚫 Conditional Access blocked
        @{ Name = "Trusted device (AzureAD joined)"; Points = -2 }, # ✅ Trusted device
        @{ Name = "Location: Netherlands"; Points = -2 }, # 🇳🇱 Local sign-in
        @{ Name = "Compliant device"; Points = -3 }, # 🛡️ Compliant device
        @{ Name = "Login outside working hours"; Points = 1 }, # ⏰ Time anomaly
        @{ Name = "Suspicious IP (AbuseIPDB + ASN)"; Points = 2 }, # 🛰️ IP + ASN combined risk
        @{ Name = "🌍 Country switch during session"; Points = 2 }, 
        @{ Name = "🔁 Multiple IPs in session"; Points = 1 },
        @{ Name = "💻 Device change in session"; Points = 1 }
    )

    # 🔢 Calculate the maximum achievable score based on defined risk indicators
    [int]$maxScoreModel = ($possibleIocs | Where-Object { $_.Points -gt 0 } | Measure-Object -Property Points -Sum).Sum                           

    # ➕ Add IOC scoring results from modular sources

        # 🌐 Session anomaly scoring
# 🚨 Add +2 risk score if any session anomaly flag is true (compound IOC)
if ($s.Session_CountryChanged -or $s.Session_IPChanged -or $s.Session_DeviceChanged) {
    $breakdown += @{ Name = "🚨 Session anomaly: IP/device/country mismatch"; Points = 5 }
}

    # 🧱 Baseline IOC’s: ...
    $baselineResults = Test-SignInBaselineIOCs -SignIn $s -WorkingHours $riskWorkingHours
    $breakdown += $baselineResults

    # 🌍 External IP/ASN IOC check
    $abuseResults = Test-SignInAbuseAsnRisk -SignIn $s -UPN $UPN
    $breakdown += $abuseResults

    # 🔐 Add only one of the related authentication IOCs based on severity
    if ($mfaFailScore -eq 1) {
        $breakdown += @{ Name = "Sign-in failed at MFA stage after valid credentials were entered"; Points = 3 }
    }
    elseif ($s.ConditionalAccessStatus -in @('failure','unknownFutureValue')) {
        $breakdown += @{ Name = "Conditional Access failure"; Points = 2 }
    }
    elseif ($s.AuthenticationDetails.Count -eq 0) {
        $breakdown += @{ Name = "No MFA used"; Points = 1 }
    }

        # 🧮 Calculate the total risk score for this sign-in session
        $score = ($breakdown | Measure-Object -Property Points -Sum).Sum

        # 🧮 Sum of all applicable IOC points (only IOCs that contributed to the score)
        $score = ($breakdown | Where-Object { $_.Points -ne 0 } | Measure-Object -Property Points -Sum).Sum
        $s | Add-Member -NotePropertyName MaxScore -NotePropertyValue $maxScoreModel -Force

        # 🧾 Sum of all IOC points, even those with zero value (for full visibility)
        $maxScore = ($breakdown | Measure-Object -Property Points -Sum).Sum

        # 💾 Store score and detailed breakdown in the sign-in object
        $s | Add-Member -NotePropertyName SignInScore -NotePropertyValue $score -Force
        $s | Add-Member -NotePropertyName SignInScoreBreakdown -NotePropertyValue $breakdown -Force

        # ⛔ Enforce minimum score of 0
        if ($score -lt 0) { $score = 0 }

        # 🛑 Only process sign-ins with a score above 1 as risky
        if ($score -gt 1) {
            $s | Add-Member -NotePropertyName SignInScore -NotePropertyValue $score -Force

            # 🧭 Determine risk level classification based on score thresholds
            if ($score -ge 9) {
                $riskLevel = "High"
            }
            elseif ($score -ge 6) {
                $riskLevel = "Medium"
            }
            elseif ($score -ge 3) {
                $riskLevel = "Low"
            }
            else {
                $riskLevel = "None"
            }

            # 💾 Add risk level and popup ID to sign-in object
            $s | Add-Member -NotePropertyName RiskLevel -NotePropertyValue $riskLevel -Force
            $s | Add-Member -NotePropertyName PopupId -NotePropertyValue $popupId -Force

            # 🪟 Build HTML popup content with risk breakdown
            $scoreTable = "<table><thead><tr><th>Risk Factor</th><th>Score</th></tr></thead><tbody>"
            foreach ($b in $breakdown | Where-Object { $_.Points -ne 0 }) {
                $scoreTable += "<tr><td>$($b.Name)</td><td>$($b.Points)</td></tr>"
            }
            $scoreTable += "<tr><td><strong>Total Score</strong></td><td><strong>$score</strong></td></tr></tbody></table>"

            # 📋 Generate full popup content with sign-in metadata and scores
            # 📍 Session anomaly summary (only if applicable)
            $sessionFlags = @()
            if ($s.Session_CountryChanged) { $sessionFlags += "🌍 Country switch" }
            if ($s.Session_IPChanged)      { $sessionFlags += "🔁 IP change" }
            if ($s.Session_DeviceChanged)  { $sessionFlags += "💻 Device change (OS or browser)" }

            $sessionRows = ""
            if ($sessionFlags.Count -gt 0) {
                $sessionRows = @"
            <tr><td><strong>Session Anomalies</strong></td><td>$($sessionFlags -join ' | ')</td></tr>
            <tr><td><strong>Explanation</strong></td><td>
                Sign-ins with identical session ID (<code>CorrelationId</code>) showed differences in the above parameters. 
                This may indicate session hijacking or inconsistent behavior across devices.
            </td></tr>
"@
}

# 📋 Generate full popup content with sign-in metadata and scores
$popupContent = @"
<table>
  <tr>
    <td><strong>Date</strong></td><td>$($s.CreatedDateTime)</td>
    </tr>
    <tr>
        <td><strong>IP Address</strong></td>
        <td>$($s.IpAddress)</td>
    </tr>
"@ + $sessionRows + @"
    <tr>
        <td><strong>Impossible Travel</strong></td>
        <td>$($s.ImpossibleTravelDetected -eq $true ? "Yes" : "No")</td>
    </tr> 
    <tr>
        <td><strong>Location</strong></td><td>$($s.Location.City), $($s.Location.CountryOrRegion)</td></tr>
    <tr>
        <td><strong>App</strong></td>
        <td>$($s.AppDisplayName)</td>
    </tr>
    <tr>
        <td><strong>Client</strong></td>
        <td>$($s.ClientAppUsed)</td>
    </tr>
    <tr>
        <td><strong>OS</strong></td>
        <td>$($s.DeviceDetail.OperatingSystem)</td>
    </tr>
    <tr>
        <td><strong>Browser</strong></td>
        <td>$($s.DeviceDetail.Browser)</td>
    </tr>
    <tr>
        <td><strong>CA Status</strong></td>
        <td>$($s.ConditionalAccessStatus)</td>
    </tr>
    <tr>
        <td><strong>MFA Count</strong></td>
        <td>$($s.AuthenticationDetails.Count)</td>
    </tr>
    <tr>
        <td><strong>TrustType</strong></td>
        <td>$($s.DeviceDetail.TrustType)</td>
    </tr>
    <tr>
        <td><strong>AbuseIPDB</strong></td>
        <td>
            $($s.AbuseScore)
            <span style='color:red; font-weight:bold;'>
            $(if ($s.AbuseHighScore -and $s.ASNUntrusted) { "⚠️ Suspicious ASN" } else { "" })
            </span>
        </td>
    </tr>
    <tr>
        <td><strong>Risk Level</strong></td>
        <td>$($s.RiskLevel)</td>
    </tr>
</table>
<h4>Score Calculation</h4>
$scoreTable
"@

            # 🧱 Append completed popup to HTML collection
$htmlPopups += @"
<div id='$popupId' class='popup'>
  <div class='popup-header'>
    <h3>Sign-in details</h3>
    <span class='popup-close' onclick='closePopup(`"$popupId`")'>&times;</span>
  </div>
  <div class='popup-body'>
    $popupContent
  </div>
</div>
"@

            # 📌 Add this sign-in to the list of risky entries for reporting
            $riskySignIns += $s
        }
    }

    # ✅ If no risky sign-ins were found, return a friendly message
    if (-not $riskySignIns) {
        return "<h2>Sign-In Risk Overview</h2><p>No risky sign-ins found.</p>"
    }

    # 📋 Generate summary table and inject popups
#$sessionAnomalyTypes = @()
$allSignInsWithSessionAnomalies = $signins | Where-Object {
    $_.Session_CountryChanged -or $_.Session_IPChanged -or $_.Session_DeviceChanged
}

if ($allSignInsWithSessionAnomalies.Count -eq 0) {
     # No anomalies – skip session summary block
    $sessionSummaryHtml = ""
} else {
    $sessionSummaryHtml = @"
<div style='padding: 8px 12px; background-color: #fff4e5; border-left: 4px solid orange; margin-bottom: 12px;'>
  <strong>⚠️ Session anomalies detected in $($allSignInsWithSessionAnomalies.Count) sign-ins:</strong><br>
</div>
"@
$sessionTable = @"
<table style='margin-top: 10px; width:100%; border-collapse: collapse; font-size: 0.9em; border: 1px solid #ccc;'>
  <thead style='background-color: #f1f1f1;'>
    <tr>
      <th style='padding:6px;'>Date</th>
      <th>IP Address</th>
      <th>Country</th>
      <th>App</th>
      <th>Client</th>
      <th>Session Anomaly</th>
    </tr>
  </thead>
  <tbody>
"@

foreach ($s in $allSignInsWithSessionAnomalies | Sort-Object CreatedDateTime -Descending) {
    $flags = @()
    if ($s.Session_CountryChanged) { $flags += "🌍 Country switch" }
    if ($s.Session_IPChanged)      { $flags += "🔁 IP change" }
    if ($s.Session_DeviceChanged)  { $flags += "💻 Device change" }
    $popup = if ($s.PopupId) {
        "<a href='#' onclick=`"openPopup('$($s.PopupId)')`">🔍</a>"
    } else {
        "-"
    }

    $sessionTable += "<tr>
        <td>$($s.CreatedDateTime)</td>
        <td>$($s.IpAddress)</td>
        <td>$($s.Location.CountryOrRegion)</td>
        <td>$($s.AppDisplayName)</td>
        <td>$($s.ClientAppUsed)</td>
        <td>$($flags -join ', ')</td>
    </tr>`n"
}

$sessionTable += "</tbody></table>"
$sessionSummaryHtml += $sessionTable
}
    
$html = @"
<div class='advisory-section'>
  $sessionSummaryHtml
  <table class='advisory-table'>
  <thead>
    <tr>
      <th>Date</th>
      <th>IP Address</th>
      <th>Location</th>
      <th>App</th>
      <th>AbuseIPDB</th>
      <th>Score</th>
      <th>Risk Level</th>
    </tr>
  </thead>
  <tbody>
"@

    # 🎯 Filter sign-ins with a contextual risk score of 3 or higher
    $filteredSignIns = $riskySignIns | Where-Object { $_.SignInScore -ge 3 }

    # 🚫 If no qualifying sign-ins exist, return fallback message
    if (-not $filteredSignIns) {
        return "<h2>Sign-In Risk Overview</h2><p>No sign-ins with score ≥ 4.</p>"
    }

    # 🧱 Cluster risky sign-ins with similar patterns
    # 🧩 First group by CorrelationId
    $correlationGroups = Group-SignInsByCorrelationId -SignIns $filteredSignIns

# 🔗 Then cluster each group based on behavior
$signInClusters = @()
foreach ($group in $correlationGroups) {
    $clusters = Group-SignInClusters -SignIns $group.SignIns
    $signInClusters += $clusters
}
    foreach ($cluster in ($signInClusters | Sort-Object -Property MaxRiskScore -Descending)) {
        $s = $cluster.MainRecord
        $subs = $cluster.SubRecords
        $loc = "$($s.Location.City), $($s.Location.CountryOrRegion)"
        $onclick = "onclick='openPopup(`"$($s.PopupId)`")' style='cursor:pointer;'"
        $abuseLabel = if ($s.AbuseHighScore -and $s.ASNUntrusted) {
            "<span style='color:red;' title='IOC 14: Abuse >70 + Unknown ASN'>⚠️ $($s.AbuseScore)</span>"
        } else {
            $s.AbuseScore
        }

        # 🔹 Add main sign-in entry row with popup link
        $html += "<tr class='cluster-main' $onclick>
            <td>$($s.CreatedDateTime)</td>
            <td>$($s.IpAddress)</td>
            <td>$loc</td>
            <td>$($s.AppDisplayName)</td>
            <td>$abuseLabel</td>
            <td>$($s.SignInScore) / $maxScoreModel</td>
            <td>$($s.RiskLevel)</td>
        </tr>"

        # 🔸 Add collapsible section for similar sign-ins in same cluster
        if ($subs.Count -gt 0) {
            $subTable = @"
<tr class='cluster-details'>
  <td colspan='7' style='background-color: #f9f9f9; border-top: 2px solid #0078d4; padding: 8px 12px;'>
    <details style='margin: 5px 0;'>
      <summary style='cursor:pointer; font-weight: 500; color: #0078d4;'>🔍 Show $($subs.Count) similar sign-ins</summary>
      <table style='margin-top:10px; width:100%; border-collapse: collapse; font-size: 0.9em; border: 1px solid #ccc;'>
        <thead>
          <tr style='background-color: #e2e6f0;'>
            <th style='padding: 6px;'>Date</th>
            <th>App</th>
            <th>Location</th>
            <th>Client</th>
            <th>Score</th>
            <th>Risk Level</th>
            <th>Popup</th>
          </tr>
        </thead>
        <tbody>
"@
            foreach ($sub in $subs) {
                $subCity = if ($sub.Location.City) { $sub.Location.City } else { 'Unknown' }
                $subCountry = if ($sub.Location.CountryOrRegion) { $sub.Location.CountryOrRegion } else { 'Unknown' }
                $subLoc = "$subCity, $subCountry"
                $subPopup = if ($sub.PopupId) {
                    "<a href='#' onclick=`"openPopup('$($sub.PopupId)')`">🔍</a>"
                } else {
                    "-"
                }
                $subTable += "<tr><td>$($sub.CreatedDateTime)</td><td>$($sub.AppDisplayName)</td><td>$subLoc</td><td>$($sub.ClientAppUsed)</td><td>$($sub.SignInScore)</td><td>$($sub.RiskLevel)</td><td>$subPopup</td></tr>`n"
            }

            $subTable += @"
        </tbody>
      </table>
    </details>
  </td>
</tr>
"@
            $html += $subTable
        }
    }

    # 🧠 Build JSON structure for OpenAI SignInRisk summary  
    #    – Only include sign-ins with a contextual score ≥ 2
    $allSignInsForAI = $riskySignIns | Where-Object { $_.SignInScore -ge 2 }

    # 📦 Initialise top-level JSON container
    $aisigninriskreport = @{
        SignIns = @()   # ← Each risky sign-in will be pushed into this array
    }

    foreach ($s in $allSignInsForAI) {

        # 📝 Map the key sign-in fields to a flat object for AI consumption
        $entry = @{
            Time            = $s.CreatedDateTime                               # ISO timestamp
            IP              = $s.IPAddress                                     # Source IP
            ImpossibleTravel = if ($s.ImpossibleTravelDetected) { "Yes" } else { "No" } # Impossible travel flag
            City            = $s.Location.City                                 # City (may be empty)
            Country         = $s.Location.CountryOrRegion                      # Country (may be empty)
            App             = $s.AppDisplayName                                # Application name
            Client          = $s.ClientAppUsed                                 # Client platform
            OperatingSystem = $s.DeviceDetail.OperatingSystem                 # OS reported by sign-in
            Browser         = $s.DeviceDetail.Browser                          # Browser string
            TrustType       = $s.DeviceDetail.TrustType                        # AzureAD / ServerAD / etc.
            IsCompliant     = $s.DeviceDetail.IsCompliant                      # Intune compliance flag
            CAStatus        = $s.ConditionalAccessStatus                       # CA result (success/failure)
            MFAUsed         = if ($s.AuthenticationDetails.Count -eq 0) { "None" } else { "$($s.AuthenticationDetails.Count)x" }  # MFA factor count
            MFAFailure      = if ($s.Status.FailureReason -like "*multifactor*" -or $s.Status.ErrorCode -in 500121,50074) { "Yes" } else { "No" }  # MFA fail flag
            AbuseScore      = $s.AbuseScore                                    # Raw AbuseIPDB score
            AbuseASN        = $s.ASN                                           # ASN from AbuseIPDB
            ASNTrusted      = if ($s.ASNUntrusted) { "No" } else { "Yes" }     # Trusted vs untrusted ASN
            RiskLevel       = $s.RiskLevel                                     # High / Medium / Low
            Score           = $s.SignInScore                                   # Calculated IOC score
            MaxScore        = $s.MaxScore                                      # Max possible score
            TimeOfDay       = ([datetime]$s.CreatedDateTime).ToLocalTime().ToString("HH:mm")  # Local time (for clustering)
            RiskFactors     = @()                                              # Populated in inner loop below
        }

        # ➕ Add individual IOC applicability flags
        foreach ($b in $s.SignInScoreBreakdown) {
            $entry.RiskFactors += @{
                Type    = $b.Name
                Details = if ($b.Points -ne 0) { "Applicable" } else { "Not applicable" }
            }
        }

        # ➕ Push completed entry into report array
        $aisigninriskreport.SignIns += $entry
    }


    # 🔧 Determine the root folder dynamically (2 levels up from this module)
    $modulePath   = $PSScriptRoot
    $rootFolder   = Split-Path -Path (Split-Path -Path $modulePath -Parent) -Parent
    $exportFolder = Join-Path -Path $rootFolder -ChildPath "exports"

    # 📂 Ensure the export folder exists
    if (-not (Test-Path $exportFolder)) {
        New-Item -Path $exportFolder -ItemType Directory -Force | Out-Null
    }

    # 💾 Set full export path for the sign-in risk AI report
    $exportPath = Join-Path -Path $exportFolder -ChildPath "aisigninriskreport.json"

    # 🧾 Store report in global advisory object
    $global:aiadvisory.SignInRisk += $aisigninriskreport

    # 💾 Export to JSON
    $aisigninriskreport | ConvertTo-Json -Depth 10 | Out-File -FilePath $exportPath -Encoding UTF8

    # 📝 Log success
    Write-Log -Type "Information" -Message "✅ AI sign-in risk report saved to: $exportPath"

    # 🧱 Finalise HTML content (closing tags + all pop-ups) and return to caller
    $html += "</tbody></table>"
    $html += $htmlPopups
    return $html
}