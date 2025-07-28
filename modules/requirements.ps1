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
    $requiredModules = @(
        "Microsoft.Graph",
        "ExchangeOnlineManagement"
    )

    foreach ($module in $requiredModules) {
        if (-not (Get-Module -ListAvailable -Name $module)) {
            Write-Host "📦 Installing required module: $module..." -ForegroundColor Yellow
            Write-Log -Type "Information" -Message "📦 Installing module: $module"

            try {
                Install-Module -Name $module -Scope CurrentUser -Force -ErrorAction Stop
                Write-Host "✅ Module installed: $module" -ForegroundColor Green
                Write-Log -Type "OK" -Message "✅ Module installed: $module"
            } catch {
                Write-Host "`n❌ Failed to install module: $module" -ForegroundColor Red
                Write-Log -Type "Error" -Message "❌ Failed to install module: $module – $($_.Exception.Message)"

                if ($module -like "Microsoft.Graph*") {
                    Write-Host "ℹ️ You can manually install the full Graph SDK using the following command:" -ForegroundColor Cyan
                    Write-Host "`n   Install-Module Microsoft.Graph -Scope CurrentUser`n" -ForegroundColor White
                    Write-Host "🔗 Learn more: https://learn.microsoft.com/powershell/microsoftgraph/installation" -ForegroundColor Cyan
                } else {
                    Write-Host "Please try installing it manually or check your internet connection or policy restrictions." -ForegroundColor Cyan
                }
                exit 1
            }
        } else {
            Write-Host "✔️ Module already available: $module" -ForegroundColor Gray
            Write-Log -Type "OK" -Message "✔️ Module already available: $module"
        }
    }

    # 📂 Load API key if exists
    if (Test-Path "$PSScriptRoot\..\api\apikey_abuseipdb_local.ps1") {
        . "$PSScriptRoot\..\api\apikey_abuseipdb_local.ps1"
        Write-Log -Type "Information" -Message "🔑 Loaded local AbuseIPDB API key"
    } elseif (Test-Path "$PSScriptRoot\..\api\apikey_abuseipdb.ps1") {
        . "$PSScriptRoot\..\api\apikey_abuseipdb.ps1"
        Write-Log -Type "Information" -Message "🔑 Loaded default AbuseIPDB API key"
    }

    # 🔐 Check if the API key is set correctly
    if ($global:ABUSEIPDB_APIKEY -eq "your-api-key-here" -or [string]::IsNullOrWhiteSpace($global:ABUSEIPDB_APIKEY)) {
        $global:ABUSEIPDB_APIKEY_WARNING = $true
        Write-Host "⚠️ AbuseIPDB API key is not configured. This check will be skipped." -ForegroundColor Yellow
        Write-Log -Type "Alert" -Message "⚠️ AbuseIPDB API key not configured. Abuse check will be skipped."
    } else {
        $global:ABUSEIPDB_APIKEY_WARNING = $false
        Write-Host "✅ AbuseIPDB API key is configured correctly." -ForegroundColor Green
        Write-Log -Type "OK" -Message "✅ AbuseIPDB API key is valid."
}

    # 🔍 Check if OpenAI API key is present
    $global:OPENAI_APIKEY_WARNING = $false

    try {
        if (Test-Path "$PSScriptRoot\..\api\apikey_openai_local.ps1") {
            . "$PSScriptRoot\..\api\apikey_openai_local.ps1"
            Write-Log -Type "Information" -Message "🧠 Loaded local OpenAI API key"
        } elseif (Test-Path "$PSScriptRoot\..\api\apikey_openai.ps1") {
            . "$PSScriptRoot\..\api\apikey_openai.ps1"
            Write-Log -Type "Information" -Message "🧠 Loaded default OpenAI API key"
        } else {
            Write-Host "⚠️ OpenAI API key file not found – analysis will be skipped." -ForegroundColor Yellow
            Write-Log -Type "Alert" -Message "⚠️ OpenAI API key file not found. Advisory will be skipped."
            $global:OPENAI_APIKEY_WARNING = $true
            return
        }

        if ([string]::IsNullOrWhiteSpace($apiKey)) {
            Write-Host "⚠️ OpenAI API key is not configured. This check will be skipped." -ForegroundColor Yellow
            Write-Log -Type "Alert" -Message "⚠️ OpenAI API key not configured. Advisory will be skipped."
            $global:OPENAI_APIKEY_WARNING = $true
    } else {
            Write-Host "✅ OpenAI API key loaded successfully." -ForegroundColor Green
            Write-Log -Type "OK" -Message "✅ OpenAI API key loaded successfully."
            }
    }
    catch {
        Write-Host "❌ Failed to load OpenAI API key: $($_.Exception.Message)" -ForegroundColor Red
        Write-Log -Type "Error" -Message "❌ Failed to load OpenAI API key: $($_.Exception.Message)"
        $global:OPENAI_APIKEY_WARNING = $true
    }

    Write-Host "✔️ Requirement checks complete.`n" -ForegroundColor Cyan
    Write-Log -Type "Information" -Message "🧪 Requirement checks complete."
}