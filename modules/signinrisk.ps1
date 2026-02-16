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
        Write-Log -Type "Error" -Message "Fatal error: No sign-in data found to calculate working hours."
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

    # 🔒 Load trusted IP detection module (SR-17, SR-18, SR-19)
    . "$PSScriptRoot\..\modules\ioc\signin\ioc-signin-trustedip.ps1"
    # 📊 Build trusted IP profile from CA Named Locations and sign-in history
    $trustedIpProfile = Get-TrustedIpProfile -SignIns $signins

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

        # 📊 Define the maximum theoretical IOC score model (IOC IDs: SR-01 through SR-19)
        # Points are synchronized with config/settings.json iocDefinitions.signInRisk
        $possibleIocs = @(
            @{ Name = "Legacy protocol (IMAP/POP/SMTP)"; Points = 3 },                                   # SR-01: IMAP/POP/SMTP - no MFA possible
            @{ Name = "Sign-in failed at MFA stage after valid credentials were entered"; Points = 3 },  # SR-02: MFA Failure - credential compromised
            @{ Name = "No MFA used"; Points = 2 },                                                        # SR-03: Unprotected login without MFA
            @{ Name = "Conditional Access failure"; Points = 2 },                                         # SR-04: Conditional Access policy violation
            @{ Name = "Foreign IP + AbuseIPDB score"; Points = 3 },                                      # SR-05: Foreign location based on AbuseIPDB score (1-3)
            @{ Name = "Suspicious IP (AbuseIPDB + ASN)"; Points = 3 },                                    # SR-06: High abuse score + unknown ASN
            @{ Name = "Impossible travel between sign-ins"; Points = 4 },                                 # SR-07: Geographically impossible travel detected
            @{ Name = "Login outside working hours"; Points = 1 },                                        # SR-08: Sign-in outside inferred working hours
            @{ Name = "Session anomaly: IP/device/country mismatch"; Points = 4 },                        # SR-09: IP/device/country mismatch in session
            @{ Name = "Country switch during session"; Points = 2 },                                      # SR-10: Country changed during session
            @{ Name = "Multiple IPs in session"; Points = 1 },                                            # SR-11: Multiple IPs in same session (VPN/proxy possible)
            @{ Name = "Device change in session"; Points = 1 },                                           # SR-12: Browser/OS switch during session
            @{ Name = "Trusted device (AzureAD joined)"; Points = -2 },                                   # SR-13: Azure AD joined device - safety indicator
            @{ Name = "Compliant device"; Points = -3 },                                                  # SR-14: Intune compliant device - safety indicator
            @{ Name = "Location: Netherlands"; Points = -1 },                                             # SR-15: Sign-in from expected location
            @{ Name = "Microsoft Risk Detection"; Points = 4 },                                           # SR-16: Microsoft Identity Protection signals (Entra ID P2)
            @{ Name = "Trusted Location IP"; Points = -2 },                                               # SR-17: IP is in CA Named Location marked as trusted
            @{ Name = "Frequently Used IP (MFA)"; Points = -1 },                                          # SR-18: IP used 3+ times with successful MFA
            @{ Name = "Frequently Used IP (Compliant)"; Points = -2 }                                     # SR-19: IP used 3+ times with compliant device
        )

        # 🔢 Calculate the maximum achievable score based on defined risk indicators
        [int]$maxScoreModel = ($possibleIocs | Where-Object { $_.Points -gt 0 } | Measure-Object -Property Points -Sum).Sum

        # ➕ Add IOC scoring results from modular sources
        # Points are synchronized with config/settings.json iocDefinitions.signInRisk

        # 🚨 SR-09: Session anomaly - IP/device/country mismatch in session
        # Points: 4 (per settings.json)
        if ($s.Session_CountryChanged -or $s.Session_IPChanged -or $s.Session_DeviceChanged) {
            $breakdown += @{ Name = "🚨 Session anomaly: IP/device/country mismatch"; Points = 4 }
        }

        # 🧱 Baseline IOC's: SR-01, SR-07, SR-08, SR-13, SR-14, SR-15
        $baselineResults = Test-SignInBaselineIOCs -SignIn $s -WorkingHours $riskWorkingHours
        $breakdown += $baselineResults

        # 🔒 Trusted IP IOC's: SR-17, SR-18, SR-19 (negative scoring for trusted IPs)
        $trustedIpResults = Test-SignInTrustedIpIOCs -SignIn $s -TrustedProfile $trustedIpProfile
        $breakdown += $trustedIpResults

        # 🌍 External IP/ASN IOC check: SR-05, SR-06
        $abuseResults = Test-SignInAbuseAsnRisk -SignIn $s -UPN $UPN
        $breakdown += $abuseResults

        # 🔐 Add only one of the related authentication IOCs based on severity
        # SR-02: MFA Failure - Points: 3 (per settings.json)
        if ($mfaFailScore -eq 1) {
            $breakdown += @{ Name = "Sign-in failed at MFA stage after valid credentials were entered"; Points = 3 }
        }
        # SR-04: CA Policy Failure - Points: 2 (per settings.json)
        elseif ($s.ConditionalAccessStatus -in @('failure','unknownFutureValue')) {
            $breakdown += @{ Name = "Conditional Access failure"; Points = 2 }
        }
        # SR-03: No MFA Used - Points: 2 (per settings.json)
        elseif ($s.AuthenticationDetails.Count -eq 0) {
            $breakdown += @{ Name = "No MFA used"; Points = 2 }
        }

        # 🛡️ SR-16: Microsoft Identity Protection Risk Signals (requires Entra ID P2)
        # These fields are only populated with P2 license; P1 returns null/none
        $msRiskLevel = $s.RiskLevelDuringSignIn
        $msRiskDetail = $s.RiskDetail

        # Only process if we have valid risk data (not null/none - indicates P2 is available)
        if ($msRiskLevel -and $msRiskLevel -notin @('none', 'hidden', 'unknownFutureValue', $null)) {
            # Map Microsoft risk types to readable descriptions
            $riskDetailMap = @{
                'leakedCredentials'       = 'Leaked credentials detected'
                'maliciousIPAddress'      = 'Malicious IP address'
                'passwordSpray'           = 'Password spray attack'
                'tokenIssuerAnomaly'      = 'Token issuer anomaly'
                'unfamiliarFeatures'      = 'Unfamiliar sign-in features'
                'anonymizedIPAddress'     = 'Anonymized IP (VPN/Tor)'
                'malwareLinkInEmail'      = 'Malware link in email'
                'suspiciousInboxForwarding' = 'Suspicious inbox forwarding'
                'impossibleTravel'        = 'Impossible travel (MS)'
                'investigationsThreatIntelligence' = 'Threat intelligence match'
            }

            $riskDescription = if ($msRiskDetail -and $riskDetailMap.ContainsKey($msRiskDetail)) {
                $riskDetailMap[$msRiskDetail]
            } elseif ($msRiskDetail -and $msRiskDetail -ne 'none') {
                $msRiskDetail
            } else {
                "Microsoft risk: $msRiskLevel"
            }

            # Assign points based on Microsoft's risk level
            $msRiskPoints = switch ($msRiskLevel) {
                'high'   { 4 }
                'medium' { 2 }
                'low'    { 1 }
                default  { 0 }
            }

            if ($msRiskPoints -gt 0) {
                $breakdown += @{ Name = "🛡️ Microsoft Risk: $riskDescription"; Points = $msRiskPoints }
                # Store for popup display
                $s | Add-Member -NotePropertyName MicrosoftRiskLevel -NotePropertyValue $msRiskLevel -Force
                $s | Add-Member -NotePropertyName MicrosoftRiskDetail -NotePropertyValue $riskDescription -Force
            }
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
            if ($score -ge 10) {
                $riskLevel = "Critical"
            }
            elseif ($score -ge 7) {
                $riskLevel = "High"
            }
            elseif ($score -ge 4) {
                $riskLevel = "Medium"
            }
            elseif ($score -ge 1) {
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
                $pointIcon = if ($b.Points -gt 0) { "➕" } else { "➖" }
                $scoreTable += "<tr><td>$($b.Name)</td><td>$pointIcon $($b.Points)</td></tr>"
            }
            $scoreTable += "<tr style='background-color: #2c2c31;'><td><strong>📊 Total Score</strong></td><td><strong>$score</strong></td></tr></tbody></table>"

            # Generate full popup content with sign-in metadata and scores
            # Session anomaly summary (only if applicable)
            $sessionFlags = @()
            if ($s.Session_CountryChanged) { $sessionFlags += "Country switch" }
            if ($s.Session_IPChanged)      { $sessionFlags += "IP change" }
            if ($s.Session_DeviceChanged)  { $sessionFlags += "Device change" }

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


        # Impossible travel icon and details section
        $impossibleTravelIcon = if ($s.ImpossibleTravelDetected -eq $true) { "Yes" } else { "No" }

        # 🚀 Build impossible travel details section if detected
        $impossibleTravelDetails = ""
        if ($s.ImpossibleTravelDetected -eq $true -and $s.TravelDetails) {
            $td = $s.TravelDetails
            $fromIp = if ($s.PreviousSignIn) { $s.PreviousSignIn.IpAddress } else { "Unknown" }
            $toIp = $s.IpAddress
            $prevTime = if ($s.PreviousSignIn) {
                try { ([datetime]$s.PreviousSignIn.CreatedDateTime).ToString("dd MMM yyyy HH:mm") } catch { $s.PreviousSignIn.CreatedDateTime }
            } else { "Unknown" }

            # Format time display
            $timeHours = $td.TimeHours
            $timeDisplay = if ($timeHours -lt 1) {
                "$([math]::Round($timeHours * 60)) minuten"
            } elseif ($timeHours -lt 24) {
                "$([math]::Floor($timeHours))u $([math]::Round(($timeHours % 1) * 60))m"
            } else {
                "$([math]::Round($timeHours, 1)) uur"
            }

            # Format distance with thousands separator
            $distanceFormatted = "{0:N0}" -f $td.DistanceKm
            $speedFormatted = "{0:N0}" -f $td.SpeedKmh

            # Get additional details from previous sign-in
            $prevApp = if ($s.PreviousSignIn) { $s.PreviousSignIn.AppDisplayName } else { "Unknown" }
            $prevClient = if ($s.PreviousSignIn) { $s.PreviousSignIn.ClientAppUsed } else { "Unknown" }
            $prevPopupLink = ""
            if ($s.PreviousSignIn -and $s.PreviousSignIn.PopupId) {
                $prevPopupLink = "<a href='#' onclick=`"openPopup('$($s.PreviousSignIn.PopupId)'); return false;`" style='color: #5bc0de; text-decoration: underline;'>View previous sign-in</a>"
            }

            $impossibleTravelDetails = @"
  <tr>
    <td colspan='2' style='background-color: #3d2020; border-left: 4px solid #dc3545; padding: 12px;'>
      <div style='color: #ff6b6b; margin-bottom: 8px;'>IMPOSSIBLE TRAVEL DETECTED</div>
      <table style='width: 100%; margin: 0; background: transparent;'>
        <tr><td style='padding: 4px 8px; color: #ccc;'>From:</td><td style='padding: 4px 8px;'>$($td.From) (IP: $fromIp)</td></tr>
        <tr><td style='padding: 4px 8px; color: #ccc;'>To:</td><td style='padding: 4px 8px;'>$($td.To) (IP: $toIp)</td></tr>
        <tr><td style='padding: 4px 8px; color: #ccc;'>Distance:</td><td style='padding: 4px 8px;'>$distanceFormatted km</td></tr>
        <tr><td style='padding: 4px 8px; color: #ccc;'>Time:</td><td style='padding: 4px 8px;'>$timeDisplay</td></tr>
        <tr><td style='padding: 4px 8px; color: #ccc;'>Speed:</td><td style='padding: 4px 8px;'><span style='color: #ff6b6b;'>$speedFormatted km/h</span> (Impossible: >1000 km/h)</td></tr>
        <tr><td colspan='2' style='padding: 8px; border-top: 1px solid #555;'>
          <div style='color: #aaa; font-size: 0.9em;'>
            <strong>Previous sign-in context:</strong><br>
            $prevTime | $prevApp | $prevClient
          </div>
          $prevPopupLink
        </td></tr>
      </table>
    </td>
  </tr>
"@
        }

        # Generate full popup content with sign-in metadata and scores
        $popupContent = @"
<table>
  <tr>
    <td><strong>Date</strong></td><td>$($s.CreatedDateTime)</td>
  </tr>
  <tr>
    <td><strong>IP Address</strong></td>
    <td>$($s.IpAddress)</td>
  </tr>
"@ + $sessionRows + $impossibleTravelDetails + @"
  <tr>
    <td><strong>Impossible Travel</strong></td>
    <td>$impossibleTravelIcon</td>
  </tr>
  <tr>
    <td><strong>Location</strong></td><td>$($s.Location.City), $($s.Location.CountryOrRegion)</td>
  </tr>
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
      $(if ($null -eq $s.AbuseScore -or $s.AbuseScore -eq "" -or $s.AbuseScore -eq 0) { "N/A" } else { $s.AbuseScore })
      <span style='color:red;'>
        $(if ($s.AbuseHighScore -and $s.ASNUntrusted) { "Suspicious ASN" } else { "" })
      </span>
    </td>
  </tr>
  <tr>
    <td><strong>Risk Level</strong></td>
    <td>$($s.RiskLevel)</td>
  </tr>
"@

        # Add Microsoft Risk Detection row if available (P2 only)
        if ($s.MicrosoftRiskLevel -and $s.MicrosoftRiskLevel -notin @('none', $null)) {
            $msRiskColor = switch ($s.MicrosoftRiskLevel) {
                'high'   { '#dc3545' }
                'medium' { '#f0ad4e' }
                'low'    { '#5bc0de' }
                default  { '#6c757d' }
            }
            $popupContent += @"
  <tr>
    <td><strong>Microsoft Risk</strong></td>
    <td><span style='color: $msRiskColor;'>$($s.MicrosoftRiskLevel.ToUpper())</span> - $($s.MicrosoftRiskDetail)</td>
  </tr>
"@
        }

        $popupContent += @"
</table>
<h4>📊 Score Calculation</h4>
$scoreTable
"@

        # 🧱 Append completed popup to HTML collection (with ARIA accessibility)
        $htmlPopups += @"
<div id='$popupId' class='popup' role='dialog' aria-modal='true' aria-labelledby='$popupId-title' aria-hidden='true'>
  <div class='popup-header'>
    <h3 id='$popupId-title'>Sign-in details</h3>
    <button class='popup-close' onclick='closePopup("$popupId")' aria-label='Close dialog'>&times;</button>
  </div>
  <div class='popup-body' style='overflow-y: auto !important; max-height: calc(80vh - 70px); height: auto;'>
    $popupContent
  </div>
</div>
"@

        # 📌 Add this sign-in to the list of risky entries for reporting
        $riskySignIns += $s
    }
}

# ✅ If no risky sign-ins were found, return an informative summary
if (-not $riskySignIns -or $riskySignIns.Count -eq 0) {
    return @"
<div class='advisory-section'>
  <h3>Sign-In Analysis</h3>
  <p>Analyzed <strong>$($signins.Count)</strong> sign-ins from the past 30 days.</p>
  <p>No sign-ins with elevated risk indicators were detected.</p>
  <p style='color: var(--status-good);'>All sign-in activity appears to be within normal parameters.</p>
</div>
"@
}

# 📋 Generate summary table and inject popups
$allSignInsWithSessionAnomalies = $signins | Where-Object {
    $_.Session_CountryChanged -or $_.Session_IPChanged -or $_.Session_DeviceChanged
}

if ($allSignInsWithSessionAnomalies.Count -eq 0) {
    # No anomalies – skip session summary block
    $sessionSummaryHtml = ""
} else {
    $sessionSummaryHtml = @"
<div style='padding: 8px 12px; background-color: #fff4e5; border-left: 4px solid orange; margin-bottom: 12px;'>
  <strong>Session anomalies detected in $($allSignInsWithSessionAnomalies.Count) sign-ins:</strong><br>
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
        if ($s.Session_CountryChanged) { $flags += "Country switch" }
        if ($s.Session_IPChanged)      { $flags += "IP change" }
        if ($s.Session_DeviceChanged)  { $flags += "Device change" }
        $popup = if ($s.PopupId) {
            "<a href='#' onclick=`"openPopup('$($s.PopupId)')`">View</a>"
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

# 🎯 Filter sign-ins with a contextual risk score of 1 or higher (was >= 3, now >= 1)
$filteredSignIns = $riskySignIns | Where-Object { $_.SignInScore -ge 1 }

# 📅 Generate Timeline visualization for top 5 risky sign-ins
$timelineHtml = ""
$topSignIns = $filteredSignIns | Sort-Object SignInScore -Descending | Select-Object -First 5
if ($topSignIns -and $topSignIns.Count -gt 0) {
    $timelineHtml = @"
<div class='advisory-section'>
  <h3 style='color: var(--accent-green); margin-bottom: 1rem;'>Recent Risk Events Timeline</h3>
  <div class='timeline'>
"@
    foreach ($signin in $topSignIns) {
        $timeDate = try { ([datetime]$signin.CreatedDateTime).ToString("MMM dd, HH:mm") } catch { $signin.CreatedDateTime }
        $riskMarkerClass = switch ($signin.RiskLevel) {
            "Critical" { "risk-critical" }
            "High"     { "risk-high" }
            "Medium"   { "risk-medium" }
            default    { "risk-low" }
        }
        $location = "$($signin.Location.City), $($signin.Location.CountryOrRegion)"
        $popupAttr = if ($signin.PopupId) { "onclick=`"openPopup('$($signin.PopupId)')`" style='cursor:pointer;'" } else { "" }

        $timelineHtml += @"
    <div class='timeline-item'>
      <div class='timeline-marker $riskMarkerClass'></div>
      <div class='timeline-content' $popupAttr>
        <div class='timeline-time'>$timeDate</div>
        <div class='timeline-title'>$($signin.AppDisplayName) - Score: $($signin.SignInScore)</div>
        <div class='timeline-details'>
          <span class='copy-inline'>$($signin.IpAddress) <span class='copy-icon' onclick="event.stopPropagation(); copyValue('$($signin.IpAddress)', this)" title='Copy IP'>⧉</span></span>
          | $location | $($signin.RiskLevel)
        </div>
      </div>
    </div>
"@
    }
    $timelineHtml += @"
  </div>
</div>
"@
}

$html = @"
<div class='advisory-section'>
  $sessionSummaryHtml
  $timelineHtml
  <div class='table-filter'>
    <input type='text' class='filter-input' placeholder='Filter sign-ins...' onkeyup="filterTable(this, 'signin-table')">
  </div>
  <table id='signin-table' class='advisory-table'>
    <thead>
      <tr>
        <th class='sortable' data-sort-type='date'>Date</th>
        <th class='sortable'>IP Address</th>
        <th class='sortable'>Location</th>
        <th class='sortable'>App</th>
        <th class='sortable' data-sort-type='number'>AbuseIPDB</th>
        <th class='sortable' data-sort-type='number'>Score</th>
        <th class='sortable'>Risk Level</th>
        <th class='fp-column'>Action</th>
      </tr>
    </thead>
    <tbody>
"@

# 🚫 If no qualifying sign-ins exist, return informative summary
if (-not $filteredSignIns -or $filteredSignIns.Count -eq 0) {
    return @"
<div class='advisory-section'>
  <h3>Sign-In Analysis</h3>
  <p>Analyzed <strong>$($signins.Count)</strong> sign-ins from the past 30 days.</p>
  <p>Found <strong>$($riskySignIns.Count)</strong> sign-ins with risk indicators, but all scored below the display threshold.</p>
  <p style='color: var(--status-good);'>No significant risk patterns detected.</p>
</div>
"@
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
    $abuseDisplay = if ($null -eq $s.AbuseScore -or $s.AbuseScore -eq "" -or $s.AbuseScore -eq 0) { "N/A" } else { $s.AbuseScore }
    $abuseLabel = if ($s.AbuseHighScore -and $s.ASNUntrusted) {
        "<span style='color:red;' title='SR-06: Abuse >70 + Unknown ASN'>$abuseDisplay</span>"
    } else {
        $abuseDisplay
    }


    # Generate sign-in ID based on time and IP for FP tracking
    $signInId = "si-" + ("$($s.CreatedDateTime)$($s.IpAddress)").GetHashCode().ToString("X8")

    # Add main sign-in entry row with popup link (click handled by initClickableRows via data-popup-id)
    $html += "<tr class='cluster-main' data-popup-id='$($s.PopupId)' data-signin-id='$signInId'>
        <td>$($s.CreatedDateTime)</td>
        <td><span class='copy-inline'>$($s.IpAddress) <span class='copy-icon' onclick=`"event.stopPropagation(); copyValue('$($s.IpAddress)', this)`" title='Copy IP'>⧉</span></span></td>
        <td>$loc</td>
        <td>$($s.AppDisplayName)</td>
        <td>$abuseLabel</td>
        <td>$($s.SignInScore) / $maxScoreModel</td>
        <td>$($s.RiskLevel)</td>
        <td class='fp-cell'><button class='fp-toggle' onclick=`"event.stopPropagation(); toggleFalsePositive('signIn', '$signInId')`">Mark FP</button></td>
    </tr>"

    # 🔸 Add collapsible section for similar sign-ins in same cluster
    if ($subs.Count -gt 0) {
        $subTable = @"
<tr class='cluster-details'>
  <td colspan='8' style='background-color: var(--card-dark); border-top: 2px solid var(--primary-blue); padding: 8px 12px;'>
    <details style='margin: 5px 0;'>
      <summary style='cursor:pointer; font-weight: 500; color: var(--primary-blue);'>Show $($subs.Count) similar sign-ins</summary>
      <table class='advisory-table' style='margin-top:10px; width:100%; font-size: 0.9em;'>
        <thead>
          <tr>
            <th style='padding: 6px;'>Date</th>
            <th>App</th>
            <th>Location</th>
            <th>Client</th>
            <th>Score</th>
            <th>Risk</th>
            <th>Details</th>
            <th style='width: 60px;'>Action</th>
          </tr>
        </thead>
        <tbody>
"@
        foreach ($sub in $subs) {
            $subCity = if ($sub.Location.City) { $sub.Location.City } else { 'Unknown' }
            $subCountry = if ($sub.Location.CountryOrRegion) { $sub.Location.CountryOrRegion } else { 'Unknown' }
            $subLoc = "$subCity, $subCountry"
            $subPopup = if ($sub.PopupId) {
                "<a href='#' onclick=`"openPopup('$($sub.PopupId)')`" style='color: var(--primary-blue);'>View</a>"
            } else {
                "-"
            }
            # Generate sub sign-in ID for FP tracking
            $subSignInId = "si-" + ("$($sub.CreatedDateTime)$($sub.IpAddress)").GetHashCode().ToString("X8")
            $subTable += "<tr data-signin-id='$subSignInId'><td>$($sub.CreatedDateTime)</td><td>$($sub.AppDisplayName)</td><td>$subLoc</td><td>$($sub.ClientAppUsed)</td><td>$($sub.SignInScore)</td><td>$($sub.RiskLevel)</td><td>$subPopup</td><td class='fp-cell'><button class='fp-toggle' onclick=`"event.stopPropagation(); toggleFalsePositive('signIn', '$subSignInId')`">FP</button></td></tr>`n"
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

    # 📊 Build sign-in risk data for summary display
    $allRiskySignIns = $riskySignIns | Where-Object { $_.SignInScore -ge 2 }

    # 📦 Store sign-in data in global object for summary page
    $global:aiadvisory.SignInRisk = @{
        SignIns = @($allRiskySignIns | ForEach-Object {
            # Generate stable sign-in ID for FP tracking (same logic as in table generation)
            $siId = "si-" + ("$($_.CreatedDateTime)$($_.IpAddress)").GetHashCode().ToString("X8")
            @{
                Id              = $siId
                PopupId         = $_.PopupId
                Time            = $_.CreatedDateTime
                IP              = $_.IPAddress
                ImpossibleTravel = if ($_.ImpossibleTravelDetected) { "Yes" } else { "No" }
                City            = $_.Location.City
                Country         = $_.Location.CountryOrRegion
                App             = $_.AppDisplayName
                Client          = $_.ClientAppUsed
                CAStatus        = $_.ConditionalAccessStatus
                MFAUsed         = if ($_.AuthenticationDetails.Count -eq 0) { "None" } else { "$($_.AuthenticationDetails.Count)x" }
                MFAFailure      = if ($_.Status.FailureReason -like "*multifactor*" -or $_.Status.ErrorCode -in 500121,50074) { "Yes" } else { "No" }
                AbuseScore      = if ($null -eq $_.AbuseScore -or $_.AbuseScore -eq "" -or $_.AbuseScore -eq 0) { "N/A" } else { $_.AbuseScore }
                RiskLevel       = $_.RiskLevel
                Score           = $_.SignInScore
                MicrosoftRisk   = if ($_.MicrosoftRiskLevel) { $_.MicrosoftRiskLevel } else { "N/A" }
                MicrosoftRiskDetail = if ($_.MicrosoftRiskDetail) { $_.MicrosoftRiskDetail } else { "N/A" }
                RiskFactors     = @($_.SignInScoreBreakdown | Where-Object { $_.Points -ne 0 } | ForEach-Object {
                    @{ Type = $_.Name; Details = "Applicable"; Points = $_.Points }
                })
            }
        })
    }

    Write-Log -Type "Information" -Message "📊 Stored $($allRiskySignIns.Count) sign-ins for summary display"

    # 🧱 Finalise HTML content (closing tags + all pop-ups) and return to caller
    $html += "</tbody></table>"
    $html += $htmlPopups
    return $html
}
