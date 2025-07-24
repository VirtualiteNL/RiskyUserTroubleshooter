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
function Ensure-RequiredModules {
    param (
        [string[]]$Modules = @(
            "Microsoft.Graph.Authentication",
            "Microsoft.Graph.Identity.SignIns",
            "Microsoft.Graph.Users",
            "Microsoft.Graph.Groups",
            "Microsoft.Graph.Applications",
            "ExchangeOnlineManagement"
        )
    )

    Write-Host "`n🔍 Checking for required PowerShell modules..."

    foreach ($module in $Modules) {
        $installed = Get-InstalledModule -Name $module -ErrorAction SilentlyContinue

        if (-not $installed) {
            Write-Host "📦 Module '$module' not found. Installing..." -ForegroundColor Yellow

            try {
                Install-Module -Name $module -Scope CurrentUser -Force -ErrorAction Stop
                Write-Host "✅ Module '$module' installed successfully." -ForegroundColor Green
            }
            catch {
                Write-Host "❌ Failed to install module '$module': $($_.Exception.Message)" -ForegroundColor Red
            }
        }
        else {
            Write-Host "✅ Module '$module' is already installed." -ForegroundColor Gray
        }
    }

# 📂 Load API key if exists
if (Test-Path "$PSScriptRoot\..\api\apikey_abuseipdb_local.ps1") {
    . "$PSScriptRoot\..\api\apikey_abuseipdb_local.ps1"
} elseif (Test-Path "$PSScriptRoot\..\api\apikey_abuseipdb.ps1") {
    . "$PSScriptRoot\..\api\apikey_abuseipdb.ps1"
}
# 🔐 Check if the API key is set correctly
if ($global:ABUSEIPDB_APIKEY -eq "your-api-key-here" -or [string]::IsNullOrWhiteSpace($global:ABUSEIPDB_APIKEY)) {
    $global:ABUSEIPDB_APIKEY_WARNING = $true
    Write-Host "⚠️ AbuseIPDB API key is missing or placeholder value. Abuse checks may not work." -ForegroundColor Yellow
} else {
    $global:ABUSEIPDB_APIKEY_WARNING = $false
    Write-Host "✅ AbuseIPDB API key is set correctly." -ForegroundColor Green
}
Write-Host "🔑 Current AbuseIPDB API key: $($global:ABUSEIPDB_APIKEY)" -ForegroundColor Cyan

# 🔍 Check if OpenAI API key is present
$global:OPENAI_APIKEY_WARNING = $false

try {
    if (Test-Path "$PSScriptRoot\..\api\apikey_openai_local.ps1") {
        . "$PSScriptRoot\..\api\apikey_openai_local.ps1"
    } elseif (Test-Path "$PSScriptRoot\..\api\apikey_openai.ps1") {
        . "$PSScriptRoot\..\api\apikey_openai.ps1"
    } else {
        Write-Host "⚠️ OpenAI key file not found – OpenAI analysis will be skipped."
        $global:OPENAI_APIKEY_WARNING = $true
        return
    }

    if ([string]::IsNullOrWhiteSpace($apiKey)) {
        Write-Host "⚠️ OpenAI API key is empty – OpenAI analysis will be skipped."
        $global:OPENAI_APIKEY_WARNING = $true
    } else {
        Write-Host "✅ OpenAI API key loaded successfully."
    }
}
catch {
    Write-Host "❌ Failed to check OpenAI API key: $($_.Exception.Message)"
    $global:OPENAI_APIKEY_WARNING = $true
}

    Write-Host "✔️ Requirement checks complete.`n"
}