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
  function Get-MaxRiskScore {
    param (
        [array]$Indicators
    )

    # 📊 Calculate the total possible score by summing all defined indicator points
    return ($Indicators | Measure-Object -Property Points -Sum).Sum
}

function Get-UserRiskSection {
    param (
        [string]$LogPath,
        [string]$UPN
    )

    Write-Host "🔍 Starting user risk analysis for: $UPN" -ForegroundColor Cyan
    Write-Log -Type "Information" -Message "🔍 Starting user risk scan for: $UPN"

    # 📥 Retrieve the user from Microsoft Graph
    Write-Log -Type "Information" -Message "🔎 Querying Microsoft Graph for user object..."
    $user = Get-MgUser -Filter "UserPrincipalName eq '$UPN'" -Property "Id,DisplayName,UserPrincipalName,CreatedDateTime" -ErrorAction SilentlyContinue | Select-Object -First 1

    if (-not $user) {
        Write-Host "❌ User not found: $UPN" -ForegroundColor Red
        Write-Log -Type "Error" -Message "❌ User not found via filter: $UPN"
        return "<h2>User Risk Summary</h2><p>User not found: $UPN</p>"
    }

    Write-Host "✅ User found: $($user.DisplayName)" -ForegroundColor Green
    Write-Log -Type "OK" -Message "✅ User found: $($user.DisplayName) ($($user.UserPrincipalName))"
    Write-Log -Type "Information" -Message "🕓 CreatedDateTime: $($user.CreatedDateTime)"

    # 📑 Retrieve directory audit logs (last 30 days)
    $lookBackDays = 30
    $since = (Get-Date).AddDays(-$lookBackDays).ToString('o')

    Write-Log -Type "Information" -Message "📥 Retrieving audit logs (last $lookBackDays days)..."
    $DirectoryAuditLogs = Get-MgAuditLogDirectoryAudit `
        -Filter "activityDateTime ge $since and targetResources/any(tr:tr/userPrincipalName eq '$UPN')" `
        -All

    Write-Host "📑 Retrieved $($DirectoryAuditLogs.Count) audit log events." -ForegroundColor Gray
    Write-Log -Type "Information" -Message "📑 Retrieved $($DirectoryAuditLogs.Count) audit events for $UPN"

    # 🧹 Optimization: Group repetitive audit entries to improve performance
    # Threshold configurable via settings.json (default: 10)
    $groupingThreshold = 10
    if ($global:settings -and $global:settings.auditLogGroupingThreshold) {
        $groupingThreshold = $global:settings.auditLogGroupingThreshold
    }

    # Group audit logs by ActivityDisplayName
    $activityGroups = $DirectoryAuditLogs | Group-Object ActivityDisplayName

    # Separate frequent vs rare activities
    $processedLogs = @()
    $groupedCount = 0

    foreach ($group in $activityGroups) {
        if ($group.Count -ge $groupingThreshold) {
            # For frequent activities, keep first occurrence with count metadata
            $firstEntry = $group.Group | Select-Object -First 1
            $firstEntry | Add-Member -NotePropertyName "OccurrenceCount" -NotePropertyValue $group.Count -Force
            $firstEntry | Add-Member -NotePropertyName "IsGrouped" -NotePropertyValue $true -Force
            $processedLogs += $firstEntry
            $groupedCount++
            Write-Log -Type "Information" -Message "📊 Grouped $($group.Count)x '$($group.Name)' audit entries"
        } else {
            # Keep all rare activities
            foreach ($entry in $group.Group) {
                $entry | Add-Member -NotePropertyName "OccurrenceCount" -NotePropertyValue 1 -Force
                $entry | Add-Member -NotePropertyName "IsGrouped" -NotePropertyValue $false -Force
                $processedLogs += $entry
            }
        }
    }

    if ($groupedCount -gt 0) {
        Write-Host "📊 Optimized: Grouped $groupedCount activity types with $groupingThreshold+ occurrences" -ForegroundColor DarkYellow
        Write-Log -Type "Information" -Message "📊 Audit log optimization: $groupedCount activity types grouped (threshold: $groupingThreshold)"
    }

    $global:UserDirectoryAuditLogs = $processedLogs

    # 🧠 Structure audit logs for OpenAI export (uses processed/grouped logs)
    $global:aiadvisory.AuditLogs = $processedLogs | ForEach-Object {
        [PSCustomObject]@{
            Time           = $_.activityDateTime
            Action         = if ($_.IsGrouped) { "$($_.activityDisplayName) ($($_.OccurrenceCount)x)" } else { $_.activityDisplayName }
            InitiatedBy    = $_.initiatedBy.user.userPrincipalName
            Target         = $_.targetResources[0].userPrincipalName
            TargetDisplay  = $_.targetResources[0].displayName
            Properties     = ($_.modifiedProperties | ForEach-Object {
                                "$($_.displayName): $($_.newValue)"
                            }) -join ', '
            OccurrenceCount = $_.OccurrenceCount
            IsGrouped      = $_.IsGrouped
        }
    }

    # 📦 Initialize variables
    $directoryRoles = @()
    $activeMfa = @()
    $riskDetails = @()
    $htmlPopups = ""
    [int]$RiskScore = 0

    # 📩 Start loading IOC modules (forwarding, inbox rules, MFA, etc.)

        # 📥 Import the module that retrieves mailbox forwarding info
        . "$PSScriptRoot\..\modules\ioc\userrisk\ioc-userrisk-forwarding.ps1"
        # 📤 Retrieve mailbox forwarding configuration
        $forwarding = Get-MailboxForwardingInfo -UPN $user.UserPrincipalName

        # 📥 Retrieve mailbox delegates (shared access permissions)
        $delegates = @()
        try {
            $mbxPermissions = Get-MailboxPermission -Identity $user.UserPrincipalName -ErrorAction SilentlyContinue |
                Where-Object { $_.User -notlike "NT AUTHORITY\*" -and $_.User -notlike "S-1-*" -and $_.IsInherited -eq $false }
            if ($mbxPermissions) {
                $delegates = $mbxPermissions
            }
            Write-Log -Type "Information" -Message "Retrieved $($delegates.Count) mailbox delegates for $($user.UserPrincipalName)"
        } catch {
            Write-Log -Type "Alert" -Message "Could not retrieve mailbox delegates: $($_.Exception.Message)"
        }

        # 📥 Import the module that retrieves inbox rules
        . "$PSScriptRoot\..\modules\ioc\userrisk\ioc-userrisk-inboxrules.ps1"
        # 📩 Retrieve inbox rules for the user mailbox
        $rules = Get-MailboxInboxRules -UPN $user.UserPrincipalName

        # 📥 Import the module that enumerates MFA registrations
        . "$PSScriptRoot\..\modules\ioc\userrisk\ioc-userrisk-mfamethods.ps1"
        # 🔐 Retrieve all active MFA methods registered for this user
        $activeMfa = Get-UserMfaMethods -UserId $user.Id

        # 📥 Retrieve OAuth consent data from audit log
        . "$PSScriptRoot\..\modules\ioc\userrisk\ioc-userrisk-oauthconsent.ps1"
        $oauthApps = Get-UserOauthConsents -UPN $user.UserPrincipalName

        if (-not $global:aiadvisory.UserRisk) {
            $global:aiadvisory.UserRisk = @{}
        }
        $global:aiadvisory.UserRisk.Consents = $oauthApps

        # 🧠 Add to risk indicators
        $riskIndicators += @{
            Name      = "OAuth consents"
            Condition = ($oauthApps.Count -gt 0)
            Points    = $oauthApps.Count
        }
        # 📥 Import the module that detects admin role memberships 
        . "$PSScriptRoot\..\modules\ioc\userrisk\ioc-userrisk-adminrole.ps1"
        # 👮 Retrieve all admin roles assigned to this user
        $directoryRoles = Get-UserAdminRoles -UserId $user.Id

        # 📥 Import the module that detects recent MFA modifications
        . "$PSScriptRoot\..\modules\ioc\userrisk\ioc-userrisk-mfamodified.ps1"
        # 🕓 Retrieve recent MFA changes for this user
        $recentMfaChanges = Get-RecentMfaChanges -UPN $UPN

        # 📥 Import the module that evaluates account age
        . "$PSScriptRoot\..\modules\ioc\userrisk\ioc-userrisk-newaccount.ps1"

        # 🧾 Retrieve recent password reset events for this user
        . "$PSScriptRoot\..\modules\ioc\userrisk\ioc-userrisk-passwordreset.ps1"
        $pwdEvents = Get-UserPasswordResetEvents -UPN $UPN

        # 🧾 Check if the user account is recently created
        $isNewAccount = Test-NewUserAccount -UPN $user.UserPrincipalName -CreatedDate $user.CreatedDateTime

        # 📥 Import the Conditional Access IOC module
        . "$PSScriptRoot\..\modules\ioc\userrisk\ioc-userrisk-ca.ps1"
        
        $caResult = Get-UserCaProtectionStatus -UPN $user.UserPrincipalName -UserObject $user
        Write-Log -Type "Information" -Message "🛡️ Conditional Access protection status evaluated"

        # 📤 Separate forwarding rules from other suspicious rules
        $forwardingRules = @($rules | Where-Object { $_.ForwardTo })
        $otherSuspiciousRules = @($rules | Where-Object { $_.RedirectTo -or $_.DeleteMessage })

        # UR-04: Check both mailbox-level forwarding AND inbox rules with ForwardTo
        $hasForwarding = ($forwarding.ForwardingSmtpAddress) -or ($forwardingRules.Count -gt 0)

        # Define all risk indicators (IOC IDs: UR-01 through UR-10)
        # Points are synchronized with config/settings.json iocDefinitions.userRisk
        $riskIndicators = @(
            @{ Name = "No MFA registered";            Condition = ($activeMfa.Count -eq 0); Points = 3 },          # UR-01: Critical security risk - no MFA methods registered
            @{ Name = "Recent MFA change";            Condition = ($recentMfaChanges.Count -gt 0); Points = 1 },   # UR-02: MFA methods modified recently - potentially suspicious
            @{ Name = "Mailbox shared with others";   Condition = ($delegates.Count -gt 0); Points = 1 },          # UR-03: Mailbox has shared/delegate access
            @{ Name = "Forwarding enabled";           Condition = $hasForwarding; Points = 3 },                    # UR-04: High exfiltration risk - mailbox forwarding OR inbox rule with ForwardTo
            @{ Name = "Suspicious inbox rules";       Condition = ($otherSuspiciousRules.Count -gt 0); Points = 2 }, # UR-05: Rules that redirect or delete messages (ForwardTo excluded - covered by UR-04)
            @{ Name = "OAuth consents";               Condition = ($oauthApps.Count -gt 0); Points = 2 },          # UR-06: Third-party application access granted
            @{ Name = "Active admin role";            Condition = ($directoryRoles.Count -gt 0); Points = 2 },     # UR-07: User has elevated administrative privileges
            @{ Name = "Account < 7 days old";         Condition = $isNewAccount; Points = 2 },                     # UR-08: Account created within last 7 days
            @{ Name = "Password reset < 30 days";     Condition = ($pwdEvents.Count -gt 0); Points = 1 }           # UR-09: Password reset within last 30 days
        )
        if ($caResult -ne $null) {
            $riskIndicators += $caResult
        }

        # 🧹 Remove null entries
        $riskIndicators = $riskIndicators | Where-Object { $_ -ne $null }

        # ⚖️ Evaluate each indicator and build risk details
        $userRiskData = @{ Risks = @() }

        foreach ($check in $riskIndicators) {
            $hit = [bool]$check.Condition
            if ($hit) { $RiskScore += $check.Points }

            $riskDetails += [PSCustomObject]@{
                Criterion = $check.Name
                Status    = if ($hit) { "●" } else { "—" }
                Points    = if ($hit) { $check.Points } else { 0 }
                MaxPoints = $check.Points
            }

            $userRiskData.Risks += @{
                Type    = $check.Name
                Details = if ($hit) { "Applicable" } else { "Not applicable" }
                Points  = if ($hit) { $check.Points } else { 0 }
                MaxPoints = $check.Points
            }
        }

        # 📊 Store user risk data in global object for summary page
        # Preserve CAProtection and Consents that were set earlier
        $userRiskData.RiskScore = $RiskScore
        $userRiskData.MaxScore = ($riskIndicators | Where-Object { $_.Points -gt 0 } | Measure-Object -Property Points -Sum).Sum
        if ($userRiskData.MaxScore -eq 0) { $userRiskData.MaxScore = 20 }
        if ($global:aiadvisory.UserRisk.CAProtection) {
            $userRiskData.CAProtection = $global:aiadvisory.UserRisk.CAProtection
        }
        if ($global:aiadvisory.UserRisk.Consents) {
            $userRiskData.Consents = $global:aiadvisory.UserRisk.Consents
        }
        $global:aiadvisory.UserRisk = $userRiskData
        Write-Log -Type "Information" -Message "📊 Stored $(@($userRiskData.Risks | Where-Object { $_.Details -eq 'Applicable' }).Count) user risk indicators with score $RiskScore"

        # 🧮 Classify total score (updated thresholds)
        switch ($true) {
            { $RiskScore -ge 10 } { $RiskLevel = "Critical"; $RiskClass = "status-critical"; break }
            { $RiskScore -ge 7 }  { $RiskLevel = "High";     $RiskClass = "status-bad"; break }
            { $RiskScore -ge 4 }  { $RiskLevel = "Medium";   $RiskClass = "status-warning"; break }
            default               { $RiskLevel = "Low";      $RiskClass = "status-good"; break }
        }

        # 🪟 Generate popup HTML per indicator
        $popupIdMap = @{}  # Store Criterion -> PopupId mapping
        foreach ($r in $riskDetails) {
            if ($r.Points -lt 1) { continue }

            $popupId = "popup-" + ([guid]::NewGuid().ToString())
            $popupIdMap[$r.Criterion] = $popupId
            $popupContent = ""

            # Match criterion names (use -like for flexible matching)
            switch -Wildcard ($r.Criterion) {
                "*Recent MFA change*" {
                    $popupContent = Convert-ToHtmlTable ($recentMfaChanges | Select ActivityDateTime, ActivityDisplayName, InitiatedBy)
                }
                "*Mailbox shared*" {
                    $popupContent = Convert-ToHtmlTable ($delegates | Select User, AccessRights)
                }
                "*Forwarding enabled*" {
                    # Show both mailbox-level forwarding AND inbox rules with ForwardTo
                    $forwardingContent = @()

                    # Mailbox-level forwarding
                    if ($forwarding.ForwardingSmtpAddress) {
                        $forwardingContent += [PSCustomObject]@{
                            "Source" = "Mailbox Setting"
                            "Forward To" = $forwarding.ForwardingSmtpAddress
                            "Keep Copy" = if ($forwarding.DeliverToMailboxAndForward) { "Yes" } else { "No" }
                        }
                    }

                    # Inbox rules with ForwardTo
                    foreach ($rule in $forwardingRules) {
                        $forwardTo = ($rule.ForwardTo | ForEach-Object { $_.PrimarySmtpAddress ?? $_.Name ?? $_.ToString().Split('[')[0].Trim() }) -join ', '
                        $forwardingContent += [PSCustomObject]@{
                            "Source" = "Inbox Rule: $($rule.Name)"
                            "Forward To" = $forwardTo
                            "Keep Copy" = "Yes (rule-based)"
                        }
                    }

                    $popupContent = Convert-ToHtmlTable $forwardingContent
                }
                "*Suspicious inbox rules*" {
                    # Only show RedirectTo and DeleteMessage rules (ForwardTo is covered by UR-04)
                    $popupContent = Convert-ToHtmlTable (
                        $otherSuspiciousRules | ForEach-Object {
                            $action = @()
                            $info   = @()
                            if ($_.RedirectTo) {
                                $action += "Redirect"
                                $info += "To: " + ($_.RedirectTo | ForEach-Object { $_.PrimarySmtpAddress ?? $_.Name ?? $_.ToString().Split('[')[0].Trim() }) -join ', '
                            }
                            if ($_.DeleteMessage) {
                                $action += "Delete"
                                $info += "Message will be deleted"
                            }
                            [PSCustomObject]@{
                                "Rule Name" = $_.Name
                                "Action"    = ($action -join ', ')
                                "Details"   = ($info -join ' | ')
                            }
                        }
                    )
                }
                "*OAuth consents*" {
                    $popupContent = Convert-ToHtmlTable (
                        $global:aiadvisory.UserRisk.Consents | Select Display, Consent, RiskLevel
                    )
                }
                "*Active admin role*" {
                    $popupContent = Convert-ToHtmlTable ($directoryRoles | Select RoleName)
                }
                "*No MFA registered*" {
                    if ($null -eq $activeMfa -or $activeMfa.Count -eq 0) {
                        $popupContent = "<p><strong>Warning:</strong> No MFA methods are registered for this user account. This is a critical security risk.</p>"
                    } else {
                        $popupContent = Convert-ToHtmlTable $activeMfa
                    }
                }
                "*Account*7 days*" {
                    $popupContent = "<p>This account was created on <strong>$($user.CreatedDateTime)</strong>, which is less than 7 days ago.</p>"
                }
                "*Password reset*" {
                    $popupContent = Convert-ToHtmlTable ($pwdEvents | Select activityDateTime, initiatedBy)
                }
                "*CA protection*" {
                    $popupContent = switch -Wildcard ($global:aiadvisory.UserRisk.CAProtection) {
                        "Full*" { "<p>User is <strong>fully protected</strong> by Conditional Access (MFA/device required).</p>" }
                        "Partial*" { "<p>User is protected, but <strong>not all cloud apps are covered</strong>.</p>" }
                        "Block policy*" {
                            $blockPolicyMatch = [regex]::Match($global:aiadvisory.UserRisk.CAProtection, "Block policy only: (.+)")
                            $policyName = if ($blockPolicyMatch.Success) { $blockPolicyMatch.Groups[1].Value } else { "Unknown" }
                            "<p>User is <strong>not protected</strong> by MFA/device Conditional Access policies.</p><p style='color: #f0ad4e;'>However, user is covered by a <strong>block policy</strong>: <code>$policyName</code></p><p><em>Block policies provide alternative protection by restricting access based on conditions (e.g., location, device state).</em></p>"
                        }
                        "None*" { "<p>User is <strong>not protected</strong> by any Conditional Access policy requiring MFA/device.</p>" }
                        default { "<p>No Conditional Access coverage information available.</p>" }
                    }
                }
                default {
                    $popupContent = "<p>No additional data available.</p>"
                }
            }

        # Render popup HTML block with ARIA accessibility
        $htmlPopups += @"
<div id='$popupId' class='popup' role='dialog' aria-modal='true' aria-labelledby='$popupId-title' aria-hidden='true'>
  <div class='popup-header'>
    <h3 id='$popupId-title'>$($r.Criterion)</h3>
    <button class='popup-close' onclick='closePopup("$popupId")' aria-label='Close dialog'>&times;</button>
  </div>
  <div class='popup-body' style='overflow-y: auto !important; max-height: calc(80vh - 70px); height: auto;'>
    $popupContent
  </div>
</div>
"@
    }

    # 📊 Construct risk score HTML table and embed popup logic
    $html = @"
<div class='advisory-section'>
  <table class='advisory-table' id='userrisk-table'>
    <thead>
      <tr>
        <th>Risk Indicator</th>
        <th>Status</th>
        <th>Points</th>
        <th class='fp-column'>Action</th>
      </tr>
    </thead>
    <tbody>
"@

    # Sort riskDetails and use hashtable to look up PopupIds
    $sortedRiskDetails = $riskDetails | Sort-Object -Property @{ Expression = { $_.Points }; Descending = $true }, @{ Expression = { $_.Criterion }; Descending = $false }

    # Generate indicator IDs for each risk
    $indicatorIdCounter = 1
    foreach ($r in $sortedRiskDetails) {
        $indicatorId = "ur-" + $indicatorIdCounter.ToString("00")
        $indicatorIdCounter++
        $statusColor = if ($r.Points -gt 0) { "#f0ad4e" } else { "#6c757d" }
        $popupAttr = if ($popupIdMap.ContainsKey($r.Criterion)) { " data-popup-id='$($popupIdMap[$r.Criterion])'" } else { "" }

        # Show FP button for all indicators with Points > 0 (can be intentionally configured)
        $fpButton = if ($r.Points -gt 0) {
            "<button class='fp-toggle' onclick=`"event.stopPropagation(); toggleFalsePositive('userRisk', '$indicatorId')`">Mark FP</button>"
        } else {
            ""
        }

        $html += "      <tr$popupAttr data-indicator-id='$indicatorId'><td>$($r.Criterion)</td><td style='color: $statusColor;'>$($r.Status)</td><td>$($r.Points)/$($r.MaxPoints)</td><td class='fp-cell'>$fpButton</td></tr>`n"
    }

    $html += @"
    </tbody>
  </table>
</div>
"@

    # ➕ Append all popup content to the final HTML
    $html += $htmlPopups

    # ✅ Return complete HTML fragment for user risk section
    return $html
}