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

function Group-SignInsByCorrelationId {
    param (
        [Parameter(Mandatory)]
        [array]$SignIns
    )

    Write-Log -Type "Information" -Message "🧩 Grouping sign-ins by CorrelationId..."

    $clusters = @()

    # 🔁 Group by CorrelationId (skip if empty)
    $groups = $SignIns | Where-Object { $_.CorrelationId } | Group-Object -Property CorrelationId

    foreach ($group in $groups) {
        $cluster = $group.Group
        if (-not $cluster) { continue }

        $clusters += [PSCustomObject]@{
            CorrelationId = $group.Name
            SignIns       = $cluster
        }
    }

    Write-Log -Type "OK" -Message "✅ Found $($clusters.Count) CorrelationId-based groups."
    return $clusters
}
function Group-SignInClusters {
    param (
        [Parameter(Mandatory = $true)]
        [array]$SignIns
    )

    Write-Log -Type "Information" -Message "🔗 Grouping sign-ins into clusters based on similarity..."

    $clusters = @()
    $processed = @{}

    for ($i = 0; $i -lt $SignIns.Count; $i++) {
        $current = $SignIns[$i]
        $key = "$($current.CreatedDateTime)-$($current.IpAddress)-$($current.AppDisplayName)"
        if ($processed.ContainsKey($key)) { continue }

        # 🧱 Start a new cluster with the current record
        $cluster = @($current)
        $ts1 = [datetime]$current.CreatedDateTime
        $ip1 = $current.IpAddress
        $app1 = Get-AppCategory $current.AppDisplayName
        $loc1 = "$($current.Location.City),$($current.Location.CountryOrRegion)"
        $ua1 = $current.ClientAppUsed

        for ($j = 0; $j -lt $SignIns.Count; $j++) {
            if ($i -eq $j) { continue }
            $compare = $SignIns[$j]

            $ts2 = [datetime]$compare.CreatedDateTime
            $ip2 = $compare.IpAddress
            $app2 = Get-AppCategory $compare.AppDisplayName
            $loc2 = "$($compare.Location.City),$($compare.Location.CountryOrRegion)"
            $ua2 = $compare.ClientAppUsed

            $timeDiff = [math]::Abs(($ts2 - $ts1).TotalSeconds)

            # 🤖 Adaptive match logic: strict (10s) or fuzzy (30s + matching metadata)
            $isStrictMatch = ($ip1 -eq $ip2 -and $app1 -eq $app2 -and $timeDiff -le 10)
            $isFuzzyMatch  = ($ip1 -eq $ip2 -and $app1 -eq $app2 -and $loc1 -eq $loc2 -and $ua1 -eq $ua2 -and $timeDiff -le 30)

            if ($isStrictMatch -or $isFuzzyMatch) {
                $cluster += $compare
                $processed["$($compare.CreatedDateTime)-$($compare.IpAddress)-$($compare.AppDisplayName)"] = $true
            }
        }

        # ✅ Finalize cluster object — main + optional subrecords
        if ($cluster.Count -gt 1) {
            $topSignIn = ($cluster | Where-Object { $_.PSObject.Properties.Name -contains 'SignInScore' }) |
                         Sort-Object -Property SignInScore -Descending |
                         Select-Object -First 1
            $otherSignIns = $cluster | Where-Object { $_ -ne $topSignIn }

            $clusters += [PSCustomObject]@{
                ClusterId    = "CL-$i"
                MaxRiskScore = $topSignIn.SignInScore
                MainRecord   = $topSignIn
                SubRecords   = $otherSignIns
            }
        } else {
            $clusters += [PSCustomObject]@{
                ClusterId    = "CL-$i"
                MaxRiskScore = $current.SignInScore
                MainRecord   = $current
                SubRecords   = @()
            }
        }
    }

    Write-Log -Type "OK" -Message "✅ Grouped $($clusters.Count) sign-in cluster(s)."
    return $clusters
}
