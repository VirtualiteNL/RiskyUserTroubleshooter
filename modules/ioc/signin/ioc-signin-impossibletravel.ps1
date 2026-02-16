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


function Get-GeoLocationCached {
    param([string]$IPAddress)

    # 💾 Use simple in-memory cache to avoid duplicate lookups during runtime
    if (-not $script:GeoCache) { $script:GeoCache = @{} }

    if ($script:GeoCache.ContainsKey($IPAddress)) {
        return $script:GeoCache[$IPAddress]
    }

    try {
        $resp = Invoke-RestMethod -Uri "http://ip-api.com/json/$IPAddress" -Method Get -TimeoutSec 5
        $loc  = @{
            IP      = $IPAddress
            Lat     = $resp.lat
            Lon     = $resp.lon
            City    = $resp.city
            Country = $resp.country
        }
    } catch {
        $loc = $null
    }

    $script:GeoCache[$IPAddress] = $loc
    return $loc
}

function Get-DistanceKm {
    param (
        [double]$Lat1, [double]$Lon1,
        [double]$Lat2, [double]$Lon2
    )

    $earthRadiusKm = 6371
    $dLat = ($Lat2 - $Lat1) * ([math]::PI / 180)
    $dLon = ($Lon2 - $Lon1) * ([math]::PI / 180)

    $lat1Rad = $Lat1 * ([math]::PI / 180)
    $lat2Rad = $Lat2 * ([math]::PI / 180)

    $a = [math]::Sin($dLat / 2) * [math]::Sin($dLat / 2) +
         [math]::Cos($lat1Rad) * [math]::Cos($lat2Rad) *
         [math]::Sin($dLon / 2) * [math]::Sin($dLon / 2)

    $c = 2 * [math]::Atan2([math]::Sqrt($a), [math]::Sqrt(1 - $a))
    return $earthRadiusKm * $c
}

function Test-ImpossibleTravel {
    param(
        [array]$SignIns,      # 📦 Full $signins object for a single user – sorted by CreatedDateTime
        [int]  $SpeedLimitKmH = 1000
    )

    # 🔁 Iterate through sorted sign-ins; only compare if IP address changes
    for ($i=1; $i -lt $SignIns.Count; $i++) {
        $prev = $SignIns[$i-1]
        $curr = $SignIns[$i]

        if ($prev.IpAddress -eq $curr.IpAddress) { continue }   # ⚠️ Skip comparison if IP address did not change

        $loc1 = Get-GeoLocationCached $prev.IpAddress
        $loc2 = Get-GeoLocationCached $curr.IpAddress
        if ($null -in @($loc1,$loc2)) { continue }

        $distKm = Get-DistanceKm -Lat1 $loc1.Lat -Lon1 $loc1.Lon -Lat2 $loc2.Lat -Lon2 $loc2.Lon
        $hours  = ([datetime]$curr.CreatedDateTime - [datetime]$prev.CreatedDateTime).TotalHours
        if ($hours -le 0) { continue }

        $speed = $distKm / $hours
        if ($speed -gt $SpeedLimitKmH) {
            # 🚩 Mark only the second event (current) as suspicious if threshold exceeded
            $curr | Add-Member -NotePropertyName ImpossibleTravelDetected -NotePropertyValue $true -Force
            $curr | Add-Member -NotePropertyName TravelDetails -NotePropertyValue @{
                From        = "$($loc1.City), $($loc1.Country)"
                To          = "$($loc2.City), $($loc2.Country)"
                FromIP      = $prev.IpAddress
                ToIP        = $curr.IpAddress
                DistanceKm  = [math]::Round($distKm,2)
                TimeHours   = [math]::Round($hours,2)
                SpeedKmh    = [math]::Round($speed,2)
                Detected    = $true
            } -Force
            # 📌 Store reference to the previous sign-in for context display
            $curr | Add-Member -NotePropertyName PreviousSignIn -NotePropertyValue $prev -Force
        }
    }
    return $SignIns
}