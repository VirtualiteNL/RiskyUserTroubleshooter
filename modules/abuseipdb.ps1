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
function Initialize-AbuseIpScores {
    param (
        [Parameter(Mandatory)][array]$IpAddresses
    )

    $Global:AbuseIpCache = @{}

    $uniqueIps = $IpAddresses | Where-Object { $_ -and $_ -match '^\d{1,3}(\.\d{1,3}){3}$' } | Sort-Object -Unique

    Write-Host "🔍 Starting AbuseIPDB lookup for $($uniqueIps.Count) unique IP(s)..." -ForegroundColor Cyan
    Write-Log -Type "Information" -Message "🧮 Initializing AbuseIPDB lookup for $($uniqueIps.Count) unique IPs"

    foreach ($ip in $uniqueIps) {
        if (-not $Global:AbuseIpCache.ContainsKey($ip)) {
            $null = Get-AbuseIpScore -IpAddress $ip
        }
    }

    Write-Host "✅ AbuseIPDB lookup completed." -ForegroundColor Green
    Write-Log -Type "OK" -Message "✅ AbuseIPDB lookup completed for all unique IPs."
}

function Get-AbuseIpScore {
    param (
        [Parameter(Mandatory)][string]$IpAddress
    )

    # ⏩ Use cached value if available
    if ($Global:AbuseIpCache.ContainsKey($IpAddress)) {
        Write-Log -Type "Information" -Message "📦 Cached AbuseIPDB score for $IpAddress = $($Global:AbuseIpCache[$IpAddress])"
        return $Global:AbuseIpCache[$IpAddress]
    }

    # 🔐 Load API key from file
    $apiKeyLoaded = $false
    if (Test-Path "$PSScriptRoot\..\api\apikey_abuseipdb_local.ps1") {
        . "$PSScriptRoot\..\api\apikey_abuseipdb_local.ps1"
        Write-Log -Type "Information" -Message "🔑 Loaded AbuseIPDB key from local override."
        $apiKeyLoaded = $true
    } elseif (Test-Path "$PSScriptRoot\..\api\apikey_abuseipdb.ps1") {
        . "$PSScriptRoot\..\api\apikey_abuseipdb.ps1"
        Write-Log -Type "Information" -Message "🔑 Loaded AbuseIPDB key from default location."
        $apiKeyLoaded = $true
    } else {
        Write-Host "⚠️ AbuseIPDB API key file not found – skipping IP check for $IpAddress" -ForegroundColor Yellow
        Write-Log -Type "Error" -Message "🚫 No AbuseIPDB API key file found – skipping check for $IpAddress"
        $Global:AbuseIpCache[$IpAddress] = "N/A"
        return "N/A"
    }

    # 🌐 Send API request
    $uri = "https://api.abuseipdb.com/api/v2/check?ipAddress=$IpAddress&maxAgeInDays=30"
    $headers = @{
        Key    = $global:ABUSEIPDB_APIKEY
        Accept = "application/json"
    }

    try {
        Write-Log -Type "Debug" -Message "🌐 Sending AbuseIPDB request for $IpAddress"
        $response = Invoke-RestMethod -Uri $uri -Method Get -Headers $headers -ErrorAction Stop
        $score = $response.data.abuseConfidenceScore
        $Global:AbuseIpCache[$IpAddress] = $score

        Write-Log -Type "OK" -Message "✅ AbuseIPDB score received for $IpAddress = $score"
        return $score
    }
    catch {
        Write-Host "❌ Error retrieving AbuseIPDB score for $IpAddress – using N/A." -ForegroundColor Red
        Write-Log -Type "Error" -Message "❌ Failed to retrieve AbuseIPDB score for ${IpAddress}: $($_.Exception.Message)"
        $Global:AbuseIpCache[$IpAddress] = "N/A"
        return "N/A"
    }
}
