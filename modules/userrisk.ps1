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

    $global:UserDirectoryAuditLogs = $DirectoryAuditLogs

    # 🧠 Structure audit logs for OpenAI export
    $global:aiadvisory.AuditLogs = $DirectoryAuditLogs | ForEach-Object {
        [PSCustomObject]@{
            Time           = $_.activityDateTime
            Action         = $_.activityDisplayName
            InitiatedBy    = $_.initiatedBy.user.userPrincipalName
            Target         = $_.targetResources[0].userPrincipalName
            TargetDisplay  = $_.targetResources[0].displayName
            Properties     = ($_.modifiedProperties | ForEach-Object {
                                "$($_.displayName): $($_.newValue)"
                            }) -join ', '
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

        # 🧠 Define all risk indicators
        $riskIndicators = @(
            @{ Name = "No MFA registered";         Condition = ($activeMfa.Count -eq 0); Points = 2 },
            @{ Name = "Recent MFA change";         Condition = ($recentMfaChanges.Count -gt 0); Points = 1 },
            @{ Name = "Mailbox shared with others";Condition = ($delegates.Count -gt 0); Points = 1 },
            @{ Name = "Forwarding enabled";        Condition = ($forwarding.ForwardingSmtpAddress); Points = 2 },
            @{ Name = "Suspicious inbox rules";    Condition = ($rules | Where-Object { $_.ForwardTo -or $_.RedirectTo -or $_.DeleteMessage }).Count -gt 0; Points = 1 },
            @{ Name = "OAuth consents"; Condition = ($oauthApps.Count -gt 0); Points = 2 }
            @{ Name = "Active admin role";         Condition = ($directoryRoles.Count -gt 0); Points = 1 },
            @{ Name = "Account < 7 days old";      Condition = $isNewAccount; Points = 2 },
            @{ Name = "Password reset <30 days";   Condition = ($pwdEvents.Count -gt 0); Points = 1 }
        )
        if ($caResult -ne $null) {
            $riskIndicators += $caResult
        }

        # 🧹 Remove null entries
        $riskIndicators = $riskIndicators | Where-Object { $_ -ne $null }

        # 📦 Prepare OpenAI export structure
        $aiuserriskreport = @{ Risks = @() }

        # ⚖️ Evaluate each indicator
        foreach ($check in $riskIndicators) {
            $hit = [bool]$check.Condition
            if ($hit) { $RiskScore += $check.Points }

            $riskDetails += [PSCustomObject]@{
                Criterium = $check.Name
                Status    = if ($hit) { "⚠️" } else { "✅" }
                Punten    = if ($hit) { $check.Points } else { 0 }
                MaxPoints = $check.Points
            }

            $aiuserriskreport.Risks += @{
                Type    = $check.Name
                Details = if ($hit) { "Applicable" } else { "Not applicable" }
            }
        }

        # 🧭 Determine export location
        $modulePath   = $PSScriptRoot
        $rootFolder   = Split-Path -Path (Split-Path -Path $modulePath -Parent) -Parent
        $exportFolder = Join-Path -Path $rootFolder -ChildPath "exports"
        if (-not (Test-Path $exportFolder)) {
            New-Item -Path $exportFolder -ItemType Directory -Force | Out-Null
        }

        # 💾 Export OpenAI JSON
        $exportPath = Join-Path -Path $exportFolder -ChildPath "aiuserriskreport.json"
        $global:aiadvisory.UserRisk += $aiuserriskreport
        $aiuserriskreport | ConvertTo-Json -Depth 10 | Out-File -FilePath $exportPath -Encoding UTF8
        Write-Log -Type "OK" -Message "✅ AI user risk report saved to: $exportPath"

        # 🧮 Classify total score
        switch ($true) {
            { $RiskScore -ge 9 } { $RiskLevel = "Critical"; $RiskClass = "status-bad"; break }
            { $RiskScore -ge 6 } { $RiskLevel = "High";     $RiskClass = "status-bad"; break }
            { $RiskScore -ge 3 } { $RiskLevel = "Medium";   $RiskClass = "status-warning"; break }
            default              { $RiskLevel = "Low";      $RiskClass = "status-good"; break }
        }

        # 🪟 Generate popup HTML per indicator
        foreach ($r in $riskDetails | Where-Object { $_.Punten -ge 1 }) {
            $popupId = "popup-" + ([guid]::NewGuid().ToString())
            $popupContent = ""

            switch ($r.Criterium) {
                "Recent MFA change" {
                    $popupContent = Convert-ToHtmlTable ($recentMfaChanges | Select ActivityDateTime, ActivityDisplayName, InitiatedBy)
                }
                "Mailbox shared with others" {
                    $popupContent = Convert-ToHtmlTable ($delegates | Select User, AccessRights)
                }
                "Forwarding enabled" {
                    $popupContent = Convert-ToHtmlTable @($forwarding)
                }
                "Suspicious inbox rules" {
                    $popupContent = Convert-ToHtmlTable (
                        $rules | Where-Object {
                            $_.ForwardTo -or $_.RedirectTo -or $_.DeleteMessage
                        } | ForEach-Object {
                            $action = @()
                            $info   = @()
                            if ($_.ForwardTo) {
                                $action += "Forward"
                                $info += "To: " + ($_.ForwardTo | ForEach-Object { $_.PrimarySmtpAddress ?? $_.Name ?? $_.ToString().Split('[')[0].Trim() }) -join ', '
                            }
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
                "OAuth consents" {
                    $popupContent = Convert-ToHtmlTable (
                        $global:aiadvisory.UserRisk.Consents | Select Display, Consent, RiskLevel
                    )
                }

                "Active admin role" {
                    $popupContent = Convert-ToHtmlTable ($directoryRoles | Select RoleName)
                }
                "No MFA registered" {
                    $popupContent = Convert-ToHtmlTable $activeMfa
                }
                "Account < 7 days old" {
                    $popupContent = "<p>This account was created on <strong>$($user.CreatedDateTime)</strong>, which is less than 7 days ago.</p>"
                }
                "Password reset <30 days" {
                    $popupContent = Convert-ToHtmlTable ($pwdEvents | Select activityDateTime, initiatedBy)
                }
                "CA protection" {
                    $popupContent = switch -Wildcard ($global:aiadvisory.UserRisk.CAProtection) {
                        "✅*" { "<p>User is <strong>fully protected</strong> by Conditional Access (MFA/device required).</p>" }
                        "⚠️*" { "<p>User is protected, but <strong>not all cloud apps are covered</strong>.</p>" }
                        "🚫*" { "<p>User is <strong>not protected</strong> by any Conditional Access policy requiring MFA/device.</p>" }
                        default { "<p>No Conditional Access coverage information available.</p>" }
                    }
                }
                default {
                    $popupContent = "<p>No additional data available.</p>"
                }
            }

            $r | Add-Member -NotePropertyName PopupId -NotePropertyValue $popupId -Force

        # 📄 Render popup HTML block
        $htmlPopups += @"
<div id='$popupId' class='popup'>
  <div class='popup-header'>
    <h3>$($r.Criterium)</h3>
    <span class='popup-close' onclick='closePopup(`"$popupId`")'>&times;</span>
  </div>
  <div class='popup-body'>
    $popupContent
  </div>
</div>
"@
    }

    # 📊 Construct risk score HTML table and embed popup logic
    $html = @"
<div class='advisory-section'>
  <table class='advisory-table'>
    <thead>
      <tr>
        <th>Criteria</th>
        <th>Status</th>
        <th>Points</th>
      </tr>
    </thead>
    <tbody>
"@

    foreach ($r in $riskDetails |
                Sort-Object -Property @{ Expression = { $_.Punten }; Descending = $true },
                                          @{ Expression = { $_.Criterium }; Descending = $false }) {

        $onclick = ""
        if ($r.PSObject.Properties.Name -contains "PopupId") {
            $onclick = " onclick=`"openPopup('$($r.PopupId)')`" style='cursor:pointer;'"
        }

        $html += "      <tr$onclick><td>$($r.Criterium)</td><td>$($r.Status)</td><td>$($r.Punten)/$($r.MaxPoints)</td></tr>`n"
    }

    $html += @"
    </tbody>
  </table>
  <table class='advisory-table' style='margin-top: 20px; width: auto;'>
    <thead>
      <tr>
        <th>Total Score</th>
        <th>Risk Level</th>
      </tr>
    </thead>
    <tbody>
      <tr>
        <td><span class='$RiskClass'>$RiskScore / $(Get-MaxRiskScore -Indicators $riskIndicators)</span></td>
        <td><span class='$RiskClass'>$RiskLevel</span></td>
      </tr>
    </tbody>
  </table>
</div>
"@

    # ➕ Append all popup content to the final HTML
    $html += $htmlPopups

    # ✅ Return complete HTML fragment for user risk section
    return $html
}