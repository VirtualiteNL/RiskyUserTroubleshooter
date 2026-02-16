function Get-BreachProbability {
    <#
    .SYNOPSIS
        Calculates the probability of an actual credential breach based on collected indicators.
    .DESCRIPTION
        Analyzes user risk and sign-in data to determine the likelihood that the account
        has been compromised. Returns a percentage and status.
    .OUTPUTS
        Hashtable with Percentage, Status, StatusClass, and Indicators
    #>
    [CmdletBinding()]
    param()

    # Initialize category scores
    $categories = @{
        CredentialCompromise = @{ Score = 0; MaxScore = 40; Indicators = @() }
        SessionAnomalies     = @{ Score = 0; MaxScore = 35; Indicators = @() }
        ConfigWeakness       = @{ Score = 0; MaxScore = 20; Indicators = @() }
        Temporal             = @{ Score = 0; MaxScore = 5;  Indicators = @() }
    }

    $isAdmin = $false

    # Analyze User Risk indicators
    if ($global:aiadvisory.UserRisk -and $global:aiadvisory.UserRisk.Risks) {
        foreach ($risk in $global:aiadvisory.UserRisk.Risks) {
            if ($risk.Details -eq "Applicable") {
                switch -Wildcard ($risk.Type) {
                    "*No MFA*" {
                        $categories.ConfigWeakness.Score += 8
                        $categories.ConfigWeakness.Indicators += "No MFA registered"
                    }
                    "*Recent MFA change*" {
                        $categories.CredentialCompromise.Score += 10
                        $categories.CredentialCompromise.Indicators += "Recent MFA modification"
                    }
                    "*Forwarding*" {
                        $categories.ConfigWeakness.Score += 8
                        $categories.ConfigWeakness.Indicators += "Email forwarding enabled"
                    }
                    "*Suspicious inbox*" {
                        $categories.ConfigWeakness.Score += 4
                        $categories.ConfigWeakness.Indicators += "Suspicious inbox rules"
                    }
                    "*admin role*" {
                        $isAdmin = $true
                    }
                    "*Password reset*" {
                        $categories.CredentialCompromise.Score += 8
                        $categories.CredentialCompromise.Indicators += "Recent password reset"
                    }
                    "*CA protection*" {
                        $caStatus = $global:aiadvisory.UserRisk.CAProtection
                        if ($caStatus -like "*not protected*" -or $caStatus -like "*🚫*") {
                            $categories.ConfigWeakness.Score += 6
                            $categories.ConfigWeakness.Indicators += "No Conditional Access protection"
                        }
                    }
                }
            }
        }
    }

    # Analyze Sign-In Risk indicators
    if ($global:aiadvisory.SignInRisk -and $global:aiadvisory.SignInRisk.SignIns) {
        $signIns = $global:aiadvisory.SignInRisk.SignIns
        $totalSignIns = $signIns.Count

        # MFA Failures (strong credential compromise indicator)
        $mfaFailures = @($signIns | Where-Object { $_.MFAFailure -eq "Yes" })
        if ($mfaFailures.Count -gt 0) {
            $categories.CredentialCompromise.Score += [math]::Min(20, $mfaFailures.Count * 10)
            $categories.CredentialCompromise.Indicators += "$($mfaFailures.Count) MFA failure(s)"
        }

        # Impossible travel
        $impossibleTravel = @($signIns | Where-Object { $_.ImpossibleTravel -eq "Yes" })
        if ($impossibleTravel.Count -gt 0) {
            $categories.SessionAnomalies.Score += [math]::Min(15, $impossibleTravel.Count * 8)
            $categories.SessionAnomalies.Indicators += "Impossible travel detected"
        }

        # Session anomalies
        $sessionAnomalies = @($signIns | Where-Object {
            $_.RiskFactors | Where-Object { $_.Type -match "Session anomaly" -and $_.Details -eq "Applicable" }
        })
        if ($sessionAnomalies.Count -gt 0) {
            $categories.SessionAnomalies.Score += [math]::Min(15, $sessionAnomalies.Count * 5)
            $categories.SessionAnomalies.Indicators += "Session anomalies detected"
        }

        # Country switches
        $countrySwitches = @($signIns | Where-Object {
            $_.RiskFactors | Where-Object { $_.Type -match "Country switch" -and $_.Details -eq "Applicable" }
        })
        if ($countrySwitches.Count -gt 0) {
            $categories.SessionAnomalies.Score += [math]::Min(10, $countrySwitches.Count * 3)
            $categories.SessionAnomalies.Indicators += "Country switches during sessions"
        }

        # Temporal concentration (many events in short time)
        if ($totalSignIns -ge 5) {
            $sortedSignIns = $signIns | Sort-Object { [datetime]$_.Time } | Select-Object -First 5 -Last 5
            if ($sortedSignIns.Count -ge 2) {
                try {
                    $firstTime = [datetime]($sortedSignIns | Select-Object -First 1).Time
                    $lastTime = [datetime]($sortedSignIns | Select-Object -Last 1).Time
                    $hourSpan = ($lastTime - $firstTime).TotalHours
                    if ($hourSpan -gt 0 -and ($totalSignIns / $hourSpan) -gt 2) {
                        $categories.Temporal.Score += 5
                        $categories.Temporal.Indicators += "High activity concentration"
                    }
                } catch {
                    # Skip temporal analysis if date parsing fails
                }
            }
        }

        # Legacy protocols
        $legacyProtocols = @($signIns | Where-Object { $_.Client -match 'imap|pop|smtp|other' })
        if ($legacyProtocols.Count -gt 0) {
            $categories.ConfigWeakness.Score += 4
            $categories.ConfigWeakness.Indicators += "Legacy protocol usage"
        }
    }

    # Cap each category at its max score
    foreach ($cat in $categories.Keys) {
        if ($categories[$cat].Score -gt $categories[$cat].MaxScore) {
            $categories[$cat].Score = $categories[$cat].MaxScore
        }
    }

    # Calculate base percentage
    $totalScore = $categories.Values | ForEach-Object { $_.Score } | Measure-Object -Sum | Select-Object -ExpandProperty Sum
    $basePercentage = $totalScore

    # Apply multipliers
    $multiplier = 1.0

    # Credential indicator present
    if ($categories.CredentialCompromise.Score -gt 0) {
        $multiplier *= 1.3
    }

    # Admin account
    if ($isAdmin) {
        $multiplier *= 1.2
    }

    # Multiple categories affected
    $affectedCategories = @($categories.Values | Where-Object { $_.Score -gt 0 }).Count
    if ($affectedCategories -ge 3) {
        $multiplier *= 1.15
    }

    # Final percentage (capped at 100)
    $finalPercentage = [math]::Min(100, [math]::Round($basePercentage * $multiplier))

    # Determine status
    $status = switch ($true) {
        { $finalPercentage -ge 71 } { "High Likelihood"; break }
        { $finalPercentage -ge 41 } { "Probable"; break }
        { $finalPercentage -ge 21 } { "Possible"; break }
        default { "Unlikely" }
    }

    $statusClass = switch ($true) {
        { $finalPercentage -ge 71 } { "status-critical"; break }
        { $finalPercentage -ge 41 } { "status-bad"; break }
        { $finalPercentage -ge 21 } { "status-warning"; break }
        default { "status-good" }
    }

    $color = switch ($true) {
        { $finalPercentage -ge 71 } { "#8b0000"; break }
        { $finalPercentage -ge 41 } { "#dc3545"; break }
        { $finalPercentage -ge 21 } { "#f0ad4e"; break }
        default { "#2cc29f" }
    }

    # Collect all indicators for display
    $allIndicators = @()
    foreach ($cat in $categories.Keys) {
        $allIndicators += $categories[$cat].Indicators
    }

    return @{
        Percentage   = $finalPercentage
        Status       = $status
        StatusClass  = $statusClass
        Color        = $color
        Indicators   = $allIndicators
        Categories   = $categories
        IsAdmin      = $isAdmin
    }
}

function ConvertTo-HtmlSafeString {
    <#
    .SYNOPSIS
        Escapes HTML special characters to prevent XSS attacks.
    .PARAMETER Value
        The string value to escape.
    #>
    param([string]$Value)

    if ([string]::IsNullOrEmpty($Value)) { return "" }

    # Use .NET's built-in HTML encoding for security
    Add-Type -AssemblyName System.Web -ErrorAction SilentlyContinue
    return [System.Web.HttpUtility]::HtmlEncode($Value)
}

function Convert-ToHtmlTable {
    param (
        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [AllowEmptyCollection()]
        $Data
    )

    # Return placeholder if data is null or empty
    if ($null -eq $Data -or ($Data -is [array] -and $Data.Count -eq 0)) {
        Write-Host "No data available for HTML table." -ForegroundColor DarkYellow
        Write-Log -Type "Alert" -Message "Convert-ToHtmlTable: empty or null dataset - no HTML generated."
        return "<p><i>No data available.</i></p>"
    }

    # Ensure data is an array
    if ($Data -isnot [array]) {
        $Data = @($Data)
    }

    # Double-check after conversion
    if ($Data.Count -eq 0) {
        Write-Host "No data available for HTML table." -ForegroundColor DarkYellow
        Write-Log -Type "Alert" -Message "Convert-ToHtmlTable: empty dataset after conversion."
        return "<p><i>No data available.</i></p>"
    }

    # Build table header
    $html = "<table><thead><tr>"
    $firstRow = $Data | Select-Object -First 1

    # Handle case where first row might be null or have no properties
    if ($null -eq $firstRow -or $null -eq $firstRow.PSObject -or $null -eq $firstRow.PSObject.Properties) {
        Write-Log -Type "Alert" -Message "Convert-ToHtmlTable: first row has no properties."
        return "<p><i>No data available.</i></p>"
    }

    $columns = $firstRow.PSObject.Properties.Name
    if ($null -eq $columns -or $columns.Count -eq 0) {
        Write-Log -Type "Alert" -Message "Convert-ToHtmlTable: no columns found in data."
        return "<p><i>No data available.</i></p>"
    }

    foreach ($col in $columns) {
        $safeCol = ConvertTo-HtmlSafeString $col
        $html += "<th>$safeCol</th>"
    }
    $html += "</tr></thead><tbody>"

    # 📊 Add table rows with XSS protection
    foreach ($row in $Data) {
        $html += "<tr>"
        foreach ($col in $columns) {
            $value = $row.$col
            $safeValue = ConvertTo-HtmlSafeString ([string]$value)
            $html += "<td>$safeValue</td>"
        }
        $html += "</tr>"
    }

    $html += "</tbody></table>"

    Write-Log -Type "OK" -Message "✅ HTML table generated with $($Data.Count) rows and $($columns.Count) columns."
    return $html
}

function Convert-AdvisoryToHtml {
    param (
        [string]$Text
    )

    # 🧪 Validate input
    if (-not $Text -or $Text.Trim() -eq '') {
        Write-Log -Type "Alert" -Message "⚠️ Convert-AdvisoryToHtml: input is empty."
        Write-Host "⚠️ Advisory section is empty. Skipping..." -ForegroundColor DarkYellow
        return "<p>No advisory text available.</p>"
    }

    # 🧭 Define advisory blocks
    $sections = @{
        "📊" = @{ Title = "Overall Risk Score";        Content = "" }
        "📋" = @{ Title = "Overall Risk Assessment";   Content = "" }
        "🎯" = @{ Title = "Attack Profile Summary";    Content = "" }
        "🔧" = @{ Title = "Recommended Actions";       Content = "" }
        "🧱" = @{ Title = "Conditional Access Policy Evaluation"; Content = "" }
    }

    # 🔍 Parse lines into sections
    $lines = $Text -split "(?ms)\r?\n|\\n"
    $currentKey = ""
    foreach ($line in $lines) {
        $trimmed = $line.Trim()
        if ($trimmed.Length -ge 2 -and $sections.ContainsKey($trimmed.Substring(0,2))) {
            $currentKey = $trimmed.Substring(0,2)
            continue
        }
        if ($currentKey) {
            $sections[$currentKey].Content += $trimmed + "`n"
        }
    }

    # 🧱 Build HTML output
    $html = ""
    foreach ($key in @("📊", "📋", "🎯", "🧱", "🔧")) {
        $title   = $sections[$key].Title
        $content = $sections[$key].Content.Trim() -replace "\*\*", ""

        if (-not $content) { continue }

        if ($key -eq "🔧") {
            $tableRows = ""
            $actions = $content -split "Risk Addressed:", 0
            foreach ($a in $actions) {
                if ($a.Trim() -eq "") { continue }

                $risk    = ($a -split "Trigger:", 2)[0].Trim()
                $trigger = ($a -split "Trigger:", 2)[1] -split "Action:", 2
                $trigger = $trigger[0].Trim()
                $action  = $a -split "Action:", 2
                $action  = if ($action.Count -eq 2) { $action[1].Trim() } else { "" }

                $tableRows += "<tr><td>$risk</td><td>$trigger</td><td>$action</td></tr>`n"
            }

            $html += @"
            <div class='advisory-section'>
            <table class='advisory-table'>
                <thead><tr><th colspan='3'>$title</th></tr>
                    <tr><th>Risk Addressed</th><th>Trigger</th><th>Action</th></tr></thead>
                <tbody>$tableRows</tbody>
            </table>
            </div>
"@
        }
        else {
            $rows = ""
            foreach ($line in $content -split "`r?`n") {
                $clean = [regex]::Replace($line.Trim(), '\*\*(.+?)\*\*', '<strong>$1</strong>')
                if ($clean) {
                    $rows += "<tr><td>$clean</td></tr>`n"
                }
            }

            $html += @"
                <div class='advisory-section'>
                <table class='advisory-table'>
                    <thead><tr><th>$title</th></tr></thead>
                    <tbody>
                    $rows
                    </tbody>
                </table>
                </div>
"@
        }
    }

    if (-not $html) {
        Write-Log -Type "Alert" -Message "⚠️ Advisory HTML rendering failed: no sections parsed."
        Write-Host "⚠️ No valid advisory sections found." -ForegroundColor Yellow
        return "<p>No advisory sections detected.</p>"
    }

    Write-Log -Type "OK" -Message "✅ Advisory HTML successfully rendered."
    return $html
}

function New-RiskSummary {
    <#
    .SYNOPSIS
        Generates a risk summary with clear separation between breach signals and configuration risks.
    .DESCRIPTION
        Analyzes collected data and generates an HTML summary that clearly distinguishes:
        - Breach Signals: Evidence of actual compromise (MFA failures, impossible travel, etc.)
        - Configuration Risks: Weaknesses that make compromise easier (no MFA, no CA, etc.)
    .OUTPUTS
        HTML string containing the risk summary.
    #>
    [CmdletBinding()]
    param()

    Write-Log -Type "Information" -Message "Generating risk summary with breach/risk separation"

    # Initialize separate lists for breach signals vs configuration risks
    $breachSignals = @()           # Evidence of actual compromise
    $configurationRisks = @()      # Weaknesses that enable attacks
    $recommendations = @()
    $userRiskCount = 0
    $signInRiskCount = 0

    # Initialize ID counter for breach signals and config risks
    $breachIdCounter = 1
    $configIdCounter = 1

    # Build a mapping of user risk indicator names to their IDs (same order as userrisk.ps1)
    $userRiskIdMap = @{}
    if ($global:aiadvisory.UserRisk -and $global:aiadvisory.UserRisk.Risks) {
        $sortedRisks = $global:aiadvisory.UserRisk.Risks | Sort-Object -Property @{ Expression = { $_.Points }; Descending = $true }, @{ Expression = { $_.Type }; Descending = $false }
        $indicatorIdCounter = 1
        foreach ($risk in $sortedRisks) {
            $indicatorId = "ur-" + $indicatorIdCounter.ToString("00")
            $indicatorIdCounter++
            $userRiskIdMap[$risk.Type] = $indicatorId
        }
    }

    # Build a mapping of sign-in characteristics to their IDs
    $signInIdMap = @{}
    if ($global:aiadvisory.SignInRisk -and $global:aiadvisory.SignInRisk.SignIns) {
        foreach ($signin in $global:aiadvisory.SignInRisk.SignIns) {
            if ($signin.Id) {
                $signInIdMap[$signin.Id] = $signin
            }
        }
    }

    # ═══════════════════════════════════════════════════════════════════
    # ANALYZE USER RISK DATA
    # ═══════════════════════════════════════════════════════════════════
    if ($global:aiadvisory.UserRisk -and $global:aiadvisory.UserRisk.Risks) {
        foreach ($risk in $global:aiadvisory.UserRisk.Risks) {
            if ($risk.Details -eq "Applicable") {
                $userRiskCount++
                # Get the indicator ID for this risk type
                $indicatorId = $userRiskIdMap[$risk.Type]

                switch -Wildcard ($risk.Type) {
                    # 🚨 BREACH SIGNALS - Evidence of active compromise
                    "*Forwarding*" {
                        $breachId = "bs-" + $breachIdCounter.ToString("00")
                        $breachIdCounter++
                        $breachSignals += @{
                            Id = $breachId
                            Signal = "Email forwarding active"
                            Detail = "Mailbox is forwarding email to external address"
                            Severity = "High"
                            TriggerType = "userRisk"
                            TriggerIds = @($indicatorId)
                        }
                        $recommendations += @{
                            Risk = "Email Forwarding"; Trigger = "Possible data exfiltration"
                            Action = "Review and remove forwarding rules"
                            LinkedTo = $breachId; LinkedType = "breach"
                        }
                    }
                    "*Suspicious inbox*" {
                        $breachId = "bs-" + $breachIdCounter.ToString("00")
                        $breachIdCounter++
                        $breachSignals += @{
                            Id = $breachId
                            Signal = "Suspicious inbox rules"
                            Detail = "Rules that forward, redirect, or delete messages"
                            Severity = "High"
                            TriggerType = "userRisk"
                            TriggerIds = @($indicatorId)
                        }
                        $recommendations += @{
                            Risk = "Inbox Manipulation"; Trigger = "Possible attempt to hide activity"
                            Action = "Audit and remove suspicious inbox rules"
                            LinkedTo = $breachId; LinkedType = "breach"
                        }
                    }
                    "*Recent MFA change*" {
                        $breachId = "bs-" + $breachIdCounter.ToString("00")
                        $breachIdCounter++
                        $breachSignals += @{
                            Id = $breachId
                            Signal = "MFA recently modified"
                            Detail = "Authentication methods were recently changed"
                            Severity = "Medium"
                            TriggerType = "userRisk"
                            TriggerIds = @($indicatorId)
                        }
                        $recommendations += @{
                            Risk = "MFA Modification"; Trigger = "Possible unauthorized MFA change"
                            Action = "Verify MFA changes were made by the user"
                            LinkedTo = $breachId; LinkedType = "breach"
                        }
                    }
                    "*Password reset*" {
                        $breachId = "bs-" + $breachIdCounter.ToString("00")
                        $breachIdCounter++
                        $breachSignals += @{
                            Id = $breachId
                            Signal = "Recent password reset"
                            Detail = "Password was reset within the last 30 days"
                            Severity = "Medium"
                            TriggerType = "userRisk"
                            TriggerIds = @($indicatorId)
                        }
                        $recommendations += @{
                            Risk = "Password Reset"; Trigger = "Potentially unauthorized reset"
                            Action = "Confirm reset was initiated by legitimate user"
                            LinkedTo = $breachId; LinkedType = "breach"
                        }
                    }

                    # ⚠️ CONFIGURATION RISKS - Weaknesses that enable attacks
                    # Note: These can be marked as FP if intentionally configured (e.g., location-based CA policies)
                    "*No MFA*" {
                        $configId = "cr-" + $configIdCounter.ToString("00")
                        $configIdCounter++
                        $configurationRisks += @{
                            Id = $configId
                            Risk = "No MFA registered"
                            Detail = "Account has no multi-factor authentication"
                            Severity = "Critical"
                            TriggerType = "userRisk"
                            TriggerIds = @($indicatorId)
                        }
                        $recommendations += @{
                            Risk = "No MFA Protection"; Trigger = "Account is not protected with MFA"
                            Action = "Register MFA methods immediately"
                            LinkedTo = $configId; LinkedType = "config"
                        }
                    }
                    "*CA protection*" {
                        $caStatus = $global:aiadvisory.UserRisk.CAProtection
                        if ($caStatus -like "*None*" -or $caStatus -like "*not protected*") {
                            $configId = "cr-" + $configIdCounter.ToString("00")
                            $configIdCounter++
                            $configurationRisks += @{
                                Id = $configId
                                Risk = "No Conditional Access"
                                Detail = "User is not protected by CA policies"
                                Severity = "High"
                                TriggerType = "userRisk"
                                TriggerIds = @($indicatorId)
                            }
                            $recommendations += @{
                                Risk = "No CA Protection"; Trigger = "No policy enforcing MFA/device"
                                Action = "Add user to Conditional Access policies"
                                LinkedTo = $configId; LinkedType = "config"
                            }
                        }
                        elseif ($caStatus -like "*Partial*" -or $caStatus -like "*not all*") {
                            $configId = "cr-" + $configIdCounter.ToString("00")
                            $configIdCounter++
                            $configurationRisks += @{
                                Id = $configId
                                Risk = "Incomplete CA coverage"
                                Detail = "Not all apps are protected by CA"
                                Severity = "Medium"
                                TriggerType = "userRisk"
                                TriggerIds = @($indicatorId)
                            }
                        }
                    }
                    "*admin role*" {
                        $configId = "cr-" + $configIdCounter.ToString("00")
                        $configIdCounter++
                        $configurationRisks += @{
                            Id = $configId
                            Risk = "Admin privileges"
                            Detail = "User has administrative privileges"
                            Severity = "Medium"
                            TriggerType = "userRisk"
                            TriggerIds = @($indicatorId)
                        }
                        $recommendations += @{
                            Risk = "Privileged Access"; Trigger = "Higher impact if account is compromised"
                            Action = "Evaluate necessity of admin rights; consider PIM"
                            LinkedTo = $configId; LinkedType = "config"
                        }
                    }
                    "*OAuth*" {
                        $configId = "cr-" + $configIdCounter.ToString("00")
                        $configIdCounter++
                        $configurationRisks += @{
                            Id = $configId
                            Risk = "OAuth app access"
                            Detail = "Third-party applications have access"
                            Severity = "Low"
                            TriggerType = "userRisk"
                            TriggerIds = @($indicatorId)
                        }
                        $recommendations += @{
                            Risk = "OAuth Consents"; Trigger = "Third-party apps with access"
                            Action = "Review and revoke suspicious app permissions"
                            LinkedTo = $configId; LinkedType = "config"
                        }
                    }
                    "*Mailbox shared*" {
                        $configId = "cr-" + $configIdCounter.ToString("00")
                        $configIdCounter++
                        $configurationRisks += @{
                            Id = $configId
                            Risk = "Shared mailbox"
                            Detail = "Other users have delegate access"
                            Severity = "Low"
                            TriggerType = "userRisk"
                            TriggerIds = @($indicatorId)
                        }
                    }
                    "*Account*7 days*" {
                        $configId = "cr-" + $configIdCounter.ToString("00")
                        $configIdCounter++
                        $configurationRisks += @{
                            Id = $configId
                            Risk = "New account"
                            Detail = "Account is less than 7 days old"
                            Severity = "Low"
                            TriggerType = "userRisk"
                            TriggerIds = @($indicatorId)
                        }
                    }
                }
            }
        }
    }

    # ═══════════════════════════════════════════════════════════════════
    # ANALYZE SIGN-IN RISK DATA
    # ═══════════════════════════════════════════════════════════════════
    if ($global:aiadvisory.SignInRisk -and $global:aiadvisory.SignInRisk.SignIns) {
        $signIns = $global:aiadvisory.SignInRisk.SignIns
        $signInRiskCount = $signIns.Count

        # 🚨 BREACH SIGNALS from sign-ins
        $mfaFailures = @($signIns | Where-Object { $_.MFAFailure -eq "Yes" })
        if ($mfaFailures.Count -gt 0) {
            $breachId = "bs-" + $breachIdCounter.ToString("00")
            $breachIdCounter++
            $triggerIds = @($mfaFailures | ForEach-Object { $_.Id } | Where-Object { $_ })
            $breachSignals += @{
                Id = $breachId
                Signal = "MFA failures detected"
                Detail = "$($mfaFailures.Count) sign-in(s) with correct password but failed MFA"
                Severity = "Critical"
                TriggerType = "signIn"
                TriggerIds = $triggerIds
            }
            $recommendations += @{
                Risk = "MFA Failures"; Trigger = "Password may be compromised"
                Action = "Reset password; revoke sessions"
                LinkedTo = $breachId; LinkedType = "breach"
            }
        }

        $impossibleTravel = @($signIns | Where-Object { $_.ImpossibleTravel -eq "Yes" })
        if ($impossibleTravel.Count -gt 0) {
            $breachId = "bs-" + $breachIdCounter.ToString("00")
            $breachIdCounter++
            $triggerIds = @($impossibleTravel | ForEach-Object { $_.Id } | Where-Object { $_ })
            $breachSignals += @{
                Id = $breachId
                Signal = "Impossible travel"
                Detail = "Sign-ins from geographically impossible locations"
                Severity = "Critical"
                TriggerType = "signIn"
                TriggerIds = $triggerIds
            }
            $recommendations += @{
                Risk = "Impossible Travel"; Trigger = "Possible concurrent access from different locations"
                Action = "Verify travel; revoke sessions if suspicious"
                LinkedTo = $breachId; LinkedType = "breach"
            }
        }

        $sessionAnomalies = @($signIns | Where-Object {
            $_.RiskFactors | Where-Object { $_.Type -match "Session anomaly" -and $_.Details -eq "Applicable" }
        })
        if ($sessionAnomalies.Count -gt 0) {
            $breachId = "bs-" + $breachIdCounter.ToString("00")
            $breachIdCounter++
            $triggerIds = @($sessionAnomalies | ForEach-Object { $_.Id } | Where-Object { $_ })
            $breachSignals += @{
                Id = $breachId
                Signal = "Session anomalies"
                Detail = "$($sessionAnomalies.Count) session(s) with IP/device/country changes"
                Severity = "High"
                TriggerType = "signIn"
                TriggerIds = $triggerIds
            }
            $recommendations += @{
                Risk = "Session Hijacking"; Trigger = "Possible session takeover"
                Action = "Revoke active sessions; consider credential reset"
                LinkedTo = $breachId; LinkedType = "breach"
            }
        }

        # Microsoft Risk Detection (P2)
        $msRiskSignIns = @($signIns | Where-Object { $_.MicrosoftRisk -notin @("N/A", "none", $null) })
        if ($msRiskSignIns.Count -gt 0) {
            $breachId = "bs-" + $breachIdCounter.ToString("00")
            $breachIdCounter++
            $triggerIds = @($msRiskSignIns | ForEach-Object { $_.Id } | Where-Object { $_ })
            $msDetails = ($msRiskSignIns | Select-Object -ExpandProperty MicrosoftRiskDetail -Unique) -join ", "
            $breachSignals += @{
                Id = $breachId
                Signal = "Microsoft Risk Detection"
                Detail = "Identity Protection: $msDetails"
                Severity = "High"
                TriggerType = "signIn"
                TriggerIds = $triggerIds
            }
        }

        $highAbuseScores = @($signIns | Where-Object {
            $score = $_.AbuseScore
            if ($null -eq $score -or $score -eq "N/A" -or $score -eq "") { return $false }
            try { [int]$score -ge 50 } catch { $false }
        })
        if ($highAbuseScores.Count -gt 0) {
            $breachId = "bs-" + $breachIdCounter.ToString("00")
            $breachIdCounter++
            $triggerIds = @($highAbuseScores | ForEach-Object { $_.Id } | Where-Object { $_ })
            $breachSignals += @{
                Id = $breachId
                Signal = "Suspicious IPs detected"
                Detail = "$($highAbuseScores.Count) sign-in(s) from IPs with high abuse score"
                Severity = "High"
                TriggerType = "signIn"
                TriggerIds = $triggerIds
            }
            $recommendations += @{
                Risk = "Malicious IPs"; Trigger = "Sign-ins from potentially malicious IPs"
                Action = "Block IPs via Conditional Access"
                LinkedTo = $breachId; LinkedType = "breach"
            }
        }

        # ⚠️ CONFIGURATION RISKS from sign-ins
        $legacyProtocols = @($signIns | Where-Object { $_.Client -match 'imap|pop|smtp|other' })
        if ($legacyProtocols.Count -gt 0) {
            $configId = "cr-" + $configIdCounter.ToString("00")
            $configIdCounter++
            $triggerIds = @($legacyProtocols | ForEach-Object { $_.Id } | Where-Object { $_ })
            $configurationRisks += @{
                Id = $configId
                Risk = "Legacy protocols"
                Detail = "$($legacyProtocols.Count) sign-in(s) via IMAP/POP/SMTP (no MFA possible)"
                Severity = "High"
                TriggerType = "signIn"
                TriggerIds = $triggerIds
            }
            $recommendations += @{
                Risk = "Legacy Protocols"; Trigger = "Protocols without MFA support"
                Action = "Block legacy auth via Conditional Access"
                LinkedTo = $configId; LinkedType = "config"
            }
        }

        $noMfaUsed = @($signIns | Where-Object { $_.MFAUsed -eq "None" })
        if ($noMfaUsed.Count -gt 0) {
            $configId = "cr-" + $configIdCounter.ToString("00")
            $configIdCounter++
            $triggerIds = @($noMfaUsed | ForEach-Object { $_.Id } | Where-Object { $_ })
            $configurationRisks += @{
                Id = $configId
                Risk = "Sign-ins without MFA"
                Detail = "$($noMfaUsed.Count) successful login(s) without MFA"
                Severity = "Medium"
                TriggerType = "signIn"
                TriggerIds = $triggerIds
            }
        }

        $foreignIPs = @($signIns | Where-Object { $_.Country -ne "NL" -and $_.Country -ne "Netherlands" -and $_.Country })
        if ($foreignIPs.Count -gt 0) {
            $countries = ($foreignIPs | Select-Object -ExpandProperty Country -Unique | Where-Object { $_ }) -join ", "
            if ($countries) {
                $configId = "cr-" + $configIdCounter.ToString("00")
                $configIdCounter++
                $triggerIds = @($foreignIPs | ForEach-Object { $_.Id } | Where-Object { $_ })
                $configurationRisks += @{
                    Id = $configId
                    Risk = "Foreign sign-ins"
                    Detail = "Countries: $countries"
                    Severity = "Low"
                    TriggerType = "signIn"
                    TriggerIds = $triggerIds
                }
            }
        }
    }

    # ═══════════════════════════════════════════════════════════════════
    # CALCULATE OVERALL SCORES
    # ═══════════════════════════════════════════════════════════════════
    $highRiskSignIns = @($global:aiadvisory.SignInRisk.SignIns | Where-Object { $_.RiskLevel -in @("High", "Critical") }).Count
    $overallScore = ($userRiskCount * 2) + ($highRiskSignIns * 4) + [math]::Min($signInRiskCount, 3)
    $riskLevel = switch ($true) {
        { $overallScore -ge 12 } { "Critical"; break }
        { $overallScore -ge 8 }  { "High"; break }
        { $overallScore -ge 4 }  { "Medium"; break }
        default { "Low" }
    }
    $riskClass = switch ($riskLevel) {
        "Critical" { "status-critical" }
        "High"     { "status-bad" }
        "Medium"   { "status-warning" }
        default    { "status-good" }
    }

    # Get Breach Probability - calculate if not already done
    $breachProb = $global:aiadvisory.BreachProbability
    if (-not $breachProb -or $null -eq $breachProb.Percentage) {
        # Calculate breach probability now if not already calculated
        $breachProb = Get-BreachProbability
        $global:aiadvisory.BreachProbability = $breachProb
    }
    $breachPercentage = if ($breachProb -and $null -ne $breachProb.Percentage) { $breachProb.Percentage } else { 0 }
    $breachStatus = if ($breachProb -and $breachProb.Status) { $breachProb.Status } else { "Unlikely" }
    $breachColor = if ($breachProb -and $breachProb.Color) { $breachProb.Color } else { "#2cc29f" }

    # ═══════════════════════════════════════════════════════════════════
    # STORE RISK SUMMARY DATA FOR HTMLBUILDER
    # ═══════════════════════════════════════════════════════════════════
    $global:aiadvisory.RiskSummary = @{
        BreachSignals = $breachSignals
        ConfigRisks = $configurationRisks
    }

    # ═══════════════════════════════════════════════════════════════════
    # BUILD HTML OUTPUT
    # ═══════════════════════════════════════════════════════════════════

    # Start with empty HTML - Risk Assessment is already shown in Executive Summary
    $html = ""

    # 🚨 BREACH SIGNALS SECTION - Most important, shown first
    if ($breachSignals.Count -gt 0) {
        $criticalBreaches = @($breachSignals | Where-Object { $_.Severity -eq "Critical" })
        $highBreaches = @($breachSignals | Where-Object { $_.Severity -eq "High" })
        $mediumBreaches = @($breachSignals | Where-Object { $_.Severity -eq "Medium" })

        $html += @"
<div class='advisory-section'>
  <table class='advisory-table' id='breach-signals-table'>
    <thead>
      <tr><th colspan='3' style='color: var(--status-bad);'>Breach Signals - Evidence of Compromise</th></tr>
      <tr>
        <th style='width: 30%;'>Signal</th>
        <th style='width: 50%;'>Details</th>
        <th style='width: 20%;'>Severity</th>
      </tr>
    </thead>
    <tbody>
"@
        # Sort by severity: Critical first, then High, then Medium
        $sortedBreaches = @($criticalBreaches) + @($highBreaches) + @($mediumBreaches)
        foreach ($breach in $sortedBreaches) {
            $severityColor = switch ($breach.Severity) {
                "Critical" { "#dc3545" }
                "High"     { "#f0ad4e" }
                "Medium"   { "#5bc0de" }
                default    { "#6c757d" }
            }
            # Build trigger IDs attribute
            $triggerIdsStr = ($breach.TriggerIds -join ",")
            $breachId = $breach.Id
            $html += "      <tr class='clickable-risk' data-breach-id='$breachId' data-trigger-type='$($breach.TriggerType)' data-trigger-ids='$triggerIdsStr'><td>$($breach.Signal)</td><td>$($breach.Detail)</td><td style='color: $severityColor;'>$($breach.Severity)</td></tr>`n"
        }
        $html += @"
    </tbody>
  </table>
</div>
"@
    }

    # ⚠️ CONFIGURATION RISKS SECTION
    if ($configurationRisks.Count -gt 0) {
        $html += @"
<div class='advisory-section'>
  <table class='advisory-table' id='config-risks-table'>
    <thead>
      <tr><th colspan='3' style='color: var(--status-warning);'>Configuration Risks - Security Weaknesses</th></tr>
      <tr>
        <th style='width: 30%;'>Risk</th>
        <th style='width: 50%;'>Details</th>
        <th style='width: 20%;'>Impact</th>
      </tr>
    </thead>
    <tbody>
"@
        # Sort by severity
        $sortedRisks = $configurationRisks | Sort-Object {
            switch ($_.Severity) { "Critical" { 0 } "High" { 1 } "Medium" { 2 } "Low" { 3 } default { 4 } }
        }
        foreach ($risk in $sortedRisks) {
            $severityColor = switch ($risk.Severity) {
                "Critical" { "#dc3545" }
                "High"     { "#f0ad4e" }
                "Medium"   { "#5bc0de" }
                default    { "#6c757d" }
            }
            # Build trigger IDs attribute
            $triggerIdsStr = ($risk.TriggerIds -join ",")
            $configId = $risk.Id

            # Check if this risk can be marked as FP (default to true if not specified)
            $canBeFP = if ($null -eq $risk.CanBeFP) { $true } else { $risk.CanBeFP }

            if ($canBeFP) {
                # Clickable row - can be marked as FP
                $html += "      <tr class='clickable-risk' data-config-id='$configId' data-trigger-type='$($risk.TriggerType)' data-trigger-ids='$triggerIdsStr'><td>$($risk.Risk)</td><td>$($risk.Detail)</td><td style='color: $severityColor;'>$($risk.Severity)</td></tr>`n"
            } else {
                # Non-clickable row - objective fact, cannot be FP
                $html += "      <tr data-config-id='$configId' data-no-fp='true' title='This is an objective configuration fact'><td>$($risk.Risk)</td><td>$($risk.Detail)</td><td style='color: $severityColor;'>$($risk.Severity)</td></tr>`n"
            }
        }
        $html += @"
    </tbody>
  </table>
</div>
"@
    }

    # Recommendations section
    if ($recommendations.Count -gt 0) {
        $html += @"
<div class='advisory-section'>
  <table class='advisory-table' id='recommendations-table'>
    <thead>
      <tr><th colspan='3' style='color: var(--primary-blue);'>Recommended Actions</th></tr>
      <tr><th>Issue</th><th>Trigger</th><th>Action</th></tr>
    </thead>
    <tbody>
"@
        foreach ($rec in $recommendations) {
            $linkedTo = if ($rec.LinkedTo) { $rec.LinkedTo } else { "" }
            $linkedType = if ($rec.LinkedType) { $rec.LinkedType } else { "" }
            $canBeFP = if ($null -eq $rec.CanBeFP) { "true" } else { $rec.CanBeFP.ToString().ToLower() }
            $html += "      <tr data-linked-to='$linkedTo' data-linked-type='$linkedType' data-can-fp='$canBeFP'><td>$($rec.Risk)</td><td>$($rec.Trigger)</td><td>$($rec.Action)</td></tr>`n"
        }
        $html += @"
    </tbody>
  </table>
</div>
"@
    }

    # No risks found message
    if ($breachSignals.Count -eq 0 -and $configurationRisks.Count -eq 0) {
        $html = @"
<div class='advisory-section'>
  <table class='advisory-table'>
    <thead><tr><th>Risk Assessment</th></tr></thead>
    <tbody>
      <tr><td>
        <span class='status-good' style='font-size: 1.2em;'>Low Risk</span>
      </td></tr>
      <tr><td>
        ✅ No significant risk indicators were detected during this analysis.
      </td></tr>
    </tbody>
  </table>
</div>
"@
    }

    Write-Log -Type "OK" -Message "Risk summary generated with $($breachSignals.Count) breach signals and $($configurationRisks.Count) configuration risks"
    return $html
}
