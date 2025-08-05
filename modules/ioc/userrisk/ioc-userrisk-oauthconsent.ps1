function Get-UserOauthConsents {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)][string]$UPN
    )

    Write-Host "🔍 Retrieving directory audit logs for $UPN..." -ForegroundColor Cyan
    Write-Log -Type "Information" -Message "🔍 Retrieving directory audit logs for $UPN..."

    $lookBackDays = 30
    $since = (Get-Date).AddDays(-$lookBackDays).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")


    try {
        $allLogs = Get-MgAuditLogDirectoryAudit -Filter "activityDateTime ge $since" -All
        $AuditLogsOAUTH = $allLogs | Where-Object {
            $_.InitiatedBy.User.UserPrincipalName -eq $UPN
        }

        Write-Log -Type "Information" -Message "📁 Retrieved $($AuditLogsOAUTH.Count) audit logs initiated by $UPN"
        Write-Host "📁 Found $($AuditLogsOAUTH.Count) logs initiated by $UPN" -ForegroundColor Gray
    } catch {
        Write-Log -Type "Error" -Message "❌ Failed to retrieve audit logs for ${UPN}: $_"
        Write-Host "❌ Failed to retrieve audit logs" -ForegroundColor Red
        return @()
    }

    Write-Host "🔍 Checking audit logs for explicit OAuth2 consents..." -ForegroundColor Cyan
    Write-Log -Type "Information" -Message "🔍 Checking audit logs for explicit OAuth2 consent activity..."

    $consents = @()

    $consentEvents = $AuditLogsOAUTH | Where-Object {
        $_.ActivityDisplayName -match '(?i)consent'
    }

    Write-Log -Type "Information" -Message "📑 Found $($consentEvents.Count) consent-related audit log entries"
    Write-Host "📑 Found $($consentEvents.Count) relevant consent events" -ForegroundColor Gray

    foreach ($event in $consentEvents) {
        $appName = $event.TargetResources[0].DisplayName
        $permissionsRaw = ($event.ModifiedProperties | Where-Object { $_.DisplayName -eq "ConsentAction.Permissions" }).NewValue
        $permissionsClean = ($permissionsRaw -replace '[\[\]"{}]', '') -split ',' | ForEach-Object { $_.Trim() }
        $permissionList = ($permissionsClean -join ', ')

        # 🧠 Risk classification logic
        $riskScore = 0
        $factors = @()

        if ($permissionsList -match "(?i)Mail.ReadWrite|Mail.Send|User.ReadWrite.All|Directory") {
            $riskScore += 2
            $factors += "SensitiveScopes"
        }

        if ($event.InitiatedBy.App) {
            $riskScore += 2
            $factors += "AdminConsent"
        }

        if ($event.TargetResources[0].ModifiedProperties -match "(?i)external") {
            $riskScore += 1
            $factors += "ExternalTenant"
        }

        switch ($true) {
            { $riskScore -ge 4 } { $riskLevel = "High" }
            { $riskScore -ge 2 } { $riskLevel = "Medium" }
            default              { $riskLevel = "Low" }
        }

        Write-Log -Type "Information" -Message "🔐 Consent granted: $appName → $permissionList (Risk: $riskLevel)"
        Write-Host "🔐 $appName → $permissionList (Risk: $riskLevel)" -ForegroundColor Yellow

        $consents += [PSCustomObject]@{
            Display     = $appName
            Consent     = $event.ActivityDateTime
            Permissions = $permissionList
            RiskLevel   = $riskLevel
            RiskFactors = ($factors -join ", ")
        }
    }

    if ($consents.Count -eq 0) {
        Write-Log -Type "OK" -Message "✅ No explicit OAuth2 consents found in audit logs."
        Write-Host "✅ No OAuth consents found in audit logs" -ForegroundColor Green
    }

    return $consents
}
