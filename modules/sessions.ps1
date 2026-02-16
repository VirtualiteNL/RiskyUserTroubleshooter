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
function Test-SignInSessionAnomalies {
    param (
        [Parameter(Mandatory = $true)][array]$SignIns
    )

    # ⛑️ Initialize default flags for all sign-ins
    foreach ($signIn in $SignIns) {
        if (-not $signIn.PSObject.Properties["Session_IPChanged"]) {
            $signIn | Add-Member -NotePropertyName Session_IPChanged -NotePropertyValue $false -Force
        }
        if (-not $signIn.PSObject.Properties["Session_CountryChanged"]) {
            $signIn | Add-Member -NotePropertyName Session_CountryChanged -NotePropertyValue $false -Force
        }
        if (-not $signIn.PSObject.Properties["Session_DeviceChanged"]) {
            $signIn | Add-Member -NotePropertyName Session_DeviceChanged -NotePropertyValue $false -Force
        }
    }

    # 📦 Group by CorrelationId
    $GroupedSessions = $SignIns | Where-Object { $_.CorrelationId } | Group-Object CorrelationId

    foreach ($session in $GroupedSessions) {
        $SessionSignIns = $session.Group

        $uniqueIPs       = $SessionSignIns.IpAddress | Sort-Object -Unique
        $uniqueCountries = $SessionSignIns.Location.Country | Sort-Object -Unique

        # 🔍 Improved device anomaly logic
        $rawDeviceIds = $SessionSignIns.DeviceDetail.DeviceId
        $nonEmpty = $rawDeviceIds | Where-Object { $_ -ne $null -and $_ -ne "" } | Sort-Object -Unique
        $hasSomeEmpty = $rawDeviceIds.Count -ne $nonEmpty.Count
        $deviceChanged = $nonEmpty.Count -ge 2
        $ipChanged      = $uniqueIPs.Count -gt 1
        $countryChanged = $uniqueCountries.Count -gt 1

        foreach ($signIn in $SessionSignIns) {
            if ($ipChanged)      { $signIn.Session_IPChanged = $true }
            if ($countryChanged) { $signIn.Session_CountryChanged = $true }
            if ($deviceChanged)  { $signIn.Session_DeviceChanged = $true }
        }

        if ($ipChanged -or $countryChanged -or $deviceChanged) {
            Write-Log -Type "Alert" -Message "⚠️ Session anomaly in CorrelationId $($session.Name): IPs=$($uniqueIPs.Count), Countries=$($uniqueCountries.Count), Devices=$($nonEmpty.Count)"
        }
    }
}

function Get-SessionAnomalySection {
    param (
        [Parameter(Mandatory = $true)][array]$SignIns
    )

    $anomalySignIns = $SignIns | Where-Object {
        $_.Session_CountryChanged -or $_.Session_IPChanged -or $_.Session_DeviceChanged
    }

    if (-not $anomalySignIns -or $anomalySignIns.Count -eq 0) {
        return ""
    }

    $html = @"
<div class='section'>
  <h2 onclick='toggle(this)'>📌 Sessions with Anomalies (toggle)</h2>
  <div style='display:none; padding: 10px; border: 1px solid #d43f00; border-radius: 8px; background-color: #fff6f4;'>
    <table>
      <thead>
        <tr style='background-color:#f2dede;'>
          <th>Date</th>
          <th>IP</th>
          <th>Location</th>
          <th>App</th>
          <th>Client</th>
          <th>OS</th>
          <th>Browser</th>
          <th>Trust</th>
          <th>MFA</th>
          <th>CA</th>
          <th>Session Anomalies</th>
        </tr>
      </thead>
      <tbody>
"@

    foreach ($s in $anomalySignIns | Sort-Object CreatedDateTime -Descending) {
        $loc = "$($s.Location.City), $($s.Location.CountryOrRegion)"
        $mfaCount = $s.AuthenticationDetails.Count
        $anomalies = @()
        if ($s.Session_CountryChanged) { $anomalies += "Country switch" }
        if ($s.Session_IPChanged)      { $anomalies += "IP change" }
        if ($s.Session_DeviceChanged)  { $anomalies += "Device change" }

        $html += "<tr>
          <td>$($s.CreatedDateTime)</td>
          <td>$($s.IpAddress)</td>
          <td>$loc</td>
          <td>$($s.AppDisplayName)</td>
          <td>$($s.ClientAppUsed)</td>
          <td>$($s.DeviceDetail.OperatingSystem)</td>
          <td>$($s.DeviceDetail.Browser)</td>
          <td>$($s.DeviceDetail.TrustType)</td>
          <td>$mfaCount</td>
          <td>$($s.ConditionalAccessStatus)</td>
          <td>$($anomalies -join ', ')</td>
        </tr>"
    }

    $html += "</tbody></table></div></div>`n"
    return $html
}