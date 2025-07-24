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
function Export-CAPolicies {
    try {
        # 🌐 Retrieve Conditional Access policies via Microsoft Graph beta endpoint
        $uri = "https://graph.microsoft.com/beta/identity/conditionalAccess/policies"
        $response = Invoke-MgGraphRequest -Method GET -Uri $uri
        $policies = $response.value

        if (-not $policies) {
            Write-Log -Type "Error" -Message "❌ No Conditional Access policies retrieved."
            return
        }

        Write-Log -Type "OK" -Message "✅ Retrieved $($policies.Count) Conditional Access policies."

        # 🧠 Parse key properties for AI consumption
        $parsed = foreach ($p in $policies) {
            @{
                Name           = $p.displayName
                State          = $p.state
                Created        = $p.createdDateTime
                LastModified   = $p.modifiedDateTime
                Conditions     = @{
                    Users          = $p.conditions.users.includeUsers
                    Apps           = $p.conditions.applications.includeApplications
                    Platforms      = $p.conditions.platforms.includePlatforms
                    Locations      = $p.conditions.locations.includeLocations
                    ClientAppTypes = $p.conditions.clientAppTypes
                }
                GrantControls   = $p.grantControls.builtInControls
                SessionControls = if ($p.sessionControls) {
                    $p.sessionControls | Get-Member -MemberType NoteProperty | ForEach-Object {
                        $_.Name
                    }
                } else {
                    @()
                }
            }
        }

        # 💾 Store parsed CA data in AI advisory object
        $global:aiadvisory.CA = $parsed
        Write-Log -Type "Information" -Message "💾 Stored Conditional Access data in global report object."

        # 📁 Export Conditional Access data as JSON to exports folder
        $exportFolder = Join-Path $PSScriptRoot "..\exports"
        if (-not (Test-Path $exportFolder)) {
            New-Item -ItemType Directory -Path $exportFolder | Out-Null
        }

        $filename = "capolicies-$($env:USERNAME)-$(Get-Date -Format 'yyyyMMdd-HHmmss').json"
        $path     = Join-Path $exportFolder $filename

        $parsed | ConvertTo-Json -Depth 10 | Set-Content -Path $path -Encoding UTF8
        Write-Log -Type "Information" -Message "📤 Exported Conditional Access policies to: $path"
    }
    catch {
        Write-Log -Type "Error" -Message "❌ Failed to export Conditional Access policies: $($_.Exception.Message)"
    }
}
