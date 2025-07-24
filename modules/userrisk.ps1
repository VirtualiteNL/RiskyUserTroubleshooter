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

    # 📥 Retrieve the user including creation date using Microsoft Graph filter
    $user = Get-MgUser -Filter "UserPrincipalName eq '$UPN'" -Property "Id,DisplayName,UserPrincipalName,CreatedDateTime" -ErrorAction SilentlyContinue | Select-Object -First 1

    if (-not $user) {
        # ❗ Return error HTML and log if the user is not found
        Write-Log -Type "Error" -Message "User not found via filter: $UPN"
        return "<h2>User Risk Summary</h2><p>User not found: $UPN</p>"
    }

    # ✅ Log user metadata for audit trail
    Write-Log -Type "Information" -Message "✅ User found: $($user.DisplayName) ($($user.UserPrincipalName))"
    Write-Log -Type "Information" -Message "🕓 CreatedDateTime: $($user.CreatedDateTime)"

    # Retrieve directory audit logs for this user (look‑back 14 days)
    $lookBackDays = 30
    $since = (Get-Date).AddDays(-$lookBackDays).ToString('o')

    $DirectoryAuditLogs = Get-MgAuditLogDirectoryAudit `
        -Filter "activityDateTime ge $since and targetResources/any(tr:tr/userPrincipalName eq '$UPN')" `
        -All

    Write-Log -Type "Information" -Message "📑 Retrieved $($DirectoryAuditLogs.Count) audit events for ${UPN}"
    $global:UserDirectoryAuditLogs = $DirectoryAuditLogs  # 🔗 Expose for IOC‑modules
    # 🧠 Structure audit logs for OpenAI context export
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
    # 📦 Initialize all working arrays and counters for scoring and HTML output
    $directoryRoles = @()
    $activeMfa = @()
    $riskDetails = @()
    $htmlPopups = ""
    [int]$RiskScore = 0

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

        # 📥 Import the module that enumerates OAuth2 app consents
        . "$PSScriptRoot\..\modules\ioc\userrisk\ioc-userrisk-oauthconsent.ps1"
        # 🔄 Retrieve all OAuth2 application consents granted by the user
        $oauthApps = Get-UserOauthConsents -UserId $user.Id

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

        # 🧠 Apply predefined user risk indicators to determine total risk score
        $riskIndicators = @(
        # 🔐 UserRisk IOC – No MFA methods registered at all
        @{ Name = "No MFA registered";         Condition = ($activeMfa.Count -eq 0); Points = 2 },

        # 🕓 UserRisk IOC – MFA method added/removed within the past 7 days
        @{ Name = "Recent MFA change";         Condition = ($recentMfaChanges.Count -gt 0); Points = 1 },

        # 👥 UserRisk IOC – Mailbox is delegated or shared with others
        @{ Name = "Mailbox shared with others";Condition = ($delegates.Count -gt 0); Points = 1 },

        # 📤 UserRisk IOC – Forwarding to external SMTP address is enabled
        @{ Name = "Forwarding enabled";        Condition = ($forwarding.ForwardingSmtpAddress); Points = 2 },

        # 📬 UserRisk IOC – Inbox rules with risky actions like forward/redirect/delete
        @{ Name = "Suspicious inbox rules";    Condition = ($rules | Where-Object { $_.ForwardTo -or $_.RedirectTo -or $_.DeleteMessage }).Count -gt 0; Points = 1 },

        # 🧾 UserRisk IOC – OAuth app consent granted
        @{ Name = "OAuth consent granted";     Condition = ($oauthApps.Count -gt 0); Points = 2 },

        # 🛡️ UserRisk IOC – User has one or more active privileged roles
        @{ Name = "Active admin role";         Condition = ($directoryRoles.Count -gt 0); Points = 1 },

        # 🧾 UserRisk IOC – User account is less than 7 days old
        @{ Name = "Account < 7 days old"; Condition = $isNewAccount; Points = 2 },

        # 🗓️ UserRisk IOC – Password reset or change within the last 7 days
        @{ Name = 'Password reset <30 days'; Condition = ($pwdEvents.Count -gt 0); Points = 1 }
    )

    # 📝 Prepare structure for OpenAI JSON export of user risk indicators
    $aiuserriskreport = @{
        Risks = @()
    }

    # 📈 Evaluate each indicator and update score, UI status, and OpenAI JSON
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

    # 🔧 Determine the root folder dynamically (2 levels up from this module)
    $modulePath   = $PSScriptRoot
    $rootFolder   = Split-Path -Path (Split-Path -Path $modulePath -Parent) -Parent
    $exportFolder = Join-Path -Path $rootFolder -ChildPath "exports"

    # 📂 Ensure the export folder exists
    if (-not (Test-Path $exportFolder)) {
        New-Item -Path $exportFolder -ItemType Directory -Force | Out-Null
    }

    # 💾 Set full export path for the user risk AI report
    $exportPath = Join-Path -Path $exportFolder -ChildPath "aiuserriskreport.json"

    # 🧠 Store report in global advisory object
    $global:aiadvisory.UserRisk += $aiuserriskreport

    # 💾 Export to JSON
    $aiuserriskreport | ConvertTo-Json -Depth 10 | Out-File -FilePath $exportPath -Encoding UTF8

    # 📝 Log success
    Write-Log -Type "Information" -Message "✅ AI user risk report saved to: $exportPath"

    # 🎯 Categorize total risk score into severity levels with corresponding UI class
    switch ($true) {
        { $RiskScore -ge 9 } { $RiskLevel = "Critical"; $RiskClass = "status-bad"; break }
        { $RiskScore -ge 6 } { $RiskLevel = "High";     $RiskClass = "status-bad"; break }
        { $RiskScore -ge 3 } { $RiskLevel = "Medium";   $RiskClass = "status-warning"; break }
        default              { $RiskLevel = "Low";      $RiskClass = "status-good"; break }
    }

    # 🪟 Generate HTML popups for all triggered risk indicators with supporting data
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
                        $toList = $_.ForwardTo | ForEach-Object {
                            if ($_.PrimarySmtpAddress) { $_.PrimarySmtpAddress }
                            elseif ($_.Name) { $_.Name }
                            else { $_.ToString().Split('[')[0].Trim() }
                        }
                        $info += "To: $($toList -join ', ')"
                    }

                    if ($_.RedirectTo) {
                        $action += "Redirect"
                        $redirList = $_.RedirectTo | ForEach-Object {
                            if ($_.PrimarySmtpAddress) { $_.PrimarySmtpAddress }
                            elseif ($_.Name) { $_.Name }
                            else { $_.ToString().Split('[')[0].Trim() }
                        }
                        $info += "To: $($redirList -join ', ')"
                    }

                    if ($_.DeleteMessage) {
                        $action += "Delete"
                        $info += "Message will be deleted"
                    }

                    [PSCustomObject]([ordered]@{
                        "Rule Name" = $_.Name
                        "Action"    = ($action -join ', ')
                        "Details"   = ($info -join ' | ')
                    })
                }
            )
    }
            "OAuth consent granted" {
                $popupContent = Convert-ToHtmlTable ($oauthApps | Select ClientId, Scope, ConsentType)
            }
            "Active admin role" {
                $popupContent = Convert-ToHtmlTable ($directoryRoles | Select RoleName)
            }
            "No MFA registered" {
                $popupContent = Convert-ToHtmlTable $activeMfa
            }
            "Account < 7 days old" {
                $popupContent = "<p>This account was created on <strong>$createdDate</strong>, which is less than 7 days ago.</p>"
            }
            'Password reset <7 days' { 
                $popupContent = Convert-ToHtmlTable ($pwdEvents | Select activityDateTime,initiatedBy) 
            }

            default {
                $popupContent = "<p>No additional data available.</p>"
            }
        }

        # 🧩 Store popup ID reference in indicator object
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
                  Sort-Object -Property @{ Expression = { $_.Punten }; Descending = $true }, @{ Expression = { $_.Criterium }; Descending = $false }) {


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

$html += $htmlPopups
return $html
}