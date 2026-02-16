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

function Load-ApiKey {
    <#
    .SYNOPSIS
        Centralized API key loading with retry logic and validation.
    .PARAMETER ApiName
        The name of the API (e.g., "abuseipdb").
    .PARAMETER VariableName
        The global variable name to store the API key.
    .OUTPUTS
        $true if API key loaded successfully, $false otherwise.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateSet("abuseipdb")]
        [string]$ApiName,

        [Parameter(Mandatory)]
        [string]$VariableName
    )

    $apiFolder = "$PSScriptRoot\..\api"
    $localPath = Join-Path $apiFolder "apikey_${ApiName}_local.ps1"
    $defaultPath = Join-Path $apiFolder "apikey_${ApiName}.ps1"

    # Try local file first, then default
    $loadedPath = $null
    if (Test-Path $localPath) {
        $loadedPath = $localPath
        . $localPath
        Write-Log -Type "Information" -Message "Loaded local $ApiName API key"
    }
    elseif (Test-Path $defaultPath) {
        $loadedPath = $defaultPath
        . $defaultPath
        Write-Log -Type "Information" -Message "Loaded default $ApiName API key"
    }
    else {
        Write-Host "API key file not found for $ApiName" -ForegroundColor Yellow
        Write-Log -Type "Alert" -Message "API key file not found for $ApiName"
        return $false
    }

    # Validate the loaded key
    $keyValue = Get-Variable -Name $VariableName -Scope Global -ValueOnly -ErrorAction SilentlyContinue

    if ($keyValue -eq "your-api-key-here" -or [string]::IsNullOrWhiteSpace($keyValue)) {
        Write-Host "$ApiName API key is not configured. This check will be skipped." -ForegroundColor Yellow
        Write-Log -Type "Alert" -Message "$ApiName API key not configured"
        return $false
    }

    Write-Host "$ApiName API key loaded successfully." -ForegroundColor Green
    Write-Log -Type "OK" -Message "$ApiName API key loaded and validated"
    return $true
}

# Global feature flags - set after API key validation
$global:FeatureFlags = @{
    AbuseIpDbEnabled = $false
}

function Initialize-FeatureFlags {
    <#
    .SYNOPSIS
        Initializes feature flags based on configuration and API key availability.
    .DESCRIPTION
        Reads the configuration and determines which features are available.
        Sets global feature flags that can be checked throughout the application.
    #>
    [CmdletBinding()]
    param()

    $config = Get-Configuration

    # Check AbuseIPDB
    $abuseIpDbEnabled = $false
    if ($config.apiKeys -and $config.apiKeys.abuseipdb) {
        $abuseIpDbEnabled = ($config.apiKeys.abuseipdb.enabled -eq $true) -and ($config.apiKeys.abuseipdb.keyConfigured -eq $true)
    }
    # Also check if API key was actually loaded successfully
    if ($abuseIpDbEnabled -and $global:ABUSEIPDB_APIKEY_WARNING) {
        $abuseIpDbEnabled = $false
    }

    $global:FeatureFlags = @{
        AbuseIpDbEnabled = $abuseIpDbEnabled
    }

    Write-Log -Type "Information" -Message "Feature flags initialized: AbuseIPDB=$($global:FeatureFlags.AbuseIpDbEnabled)"
}

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

    # 📂 Load API keys using centralized function
    $global:ABUSEIPDB_APIKEY_WARNING = -not (Load-ApiKey -ApiName "abuseipdb" -VariableName "ABUSEIPDB_APIKEY")

    # 🚩 Initialize feature flags based on configuration and loaded keys
    Initialize-FeatureFlags

    Write-Host "✔️ Requirement checks complete.`n" -ForegroundColor Cyan
    Write-Log -Type "Information" -Message "🧪 Requirement checks complete."
}