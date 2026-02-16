<#
.SYNOPSIS
    Configuration management for RiskyUserTroubleshooter

.DESCRIPTION
    Provides centralized configuration loading from settings.json with
    fallback to default values if the config file is missing or invalid.

.AUTHOR
    Danny Vorst (@Virtualite.nl)
    https://virtualite.nl | https://github.com/VirtualiteNL

.LICENSE
    Microsoft 365 Risky User Troubleshooter - Copyright & License
    Licensed for non-commercial use only.
    See LICENSE.md for full terms.
#>

# Global configuration object
$global:AppConfig = $null

function Get-Configuration {
    <#
    .SYNOPSIS
        Loads configuration from settings.json or returns cached config.
    .DESCRIPTION
        Reads the configuration file from the config directory.
        Falls back to default values if file is missing or invalid.
    .OUTPUTS
        Hashtable containing all configuration settings.
    #>
    [CmdletBinding()]
    param()

    # Return cached config if already loaded
    if ($null -ne $global:AppConfig) {
        return $global:AppConfig
    }

    # Define default configuration
    $defaultConfig = @{
        lookbackDays              = 30
        newAccountThresholdDays   = 7
        impossibleTravelSpeedKmh  = 1000
        abuseIpDbRiskThreshold    = 70
        workingHoursBufferHours   = 2
        workingHours              = @{
            start = 7
            end   = 18
        }
        trustedDutchASNs          = @("ziggo", "kpn", "t-mobile", "xs4all", "vodafone", "odido")
        riskLevels                = @{
            low      = 2
            medium   = 5
            high     = 8
            critical = 9
        }
        riskPoints                = @{
            noMfa                = 2
            recentMfaChange      = 1
            mailboxShared        = 1
            forwardingEnabled    = 2
            suspiciousInboxRules = 1
            oauthConsents        = 2
            activeAdminRole      = 1
            newAccount           = 2
            passwordReset        = 1
        }
        logging                   = @{
            level                = "Information"
            enableDebug          = $false
            enableStructuredJson = $false
        }
        api                       = @{
            maxRetries     = 3
            retryDelayMs   = 1000
            timeoutSeconds = 30
        }
        gracefulDegradation       = @{
            continueOnAbuseIpDbFailure = $true
            continueOnExchangeFailure  = $false
        }
    }

    # Locate config file
    $configPath = Join-Path -Path $PSScriptRoot -ChildPath "..\config\settings.json"

    if (-not (Test-Path $configPath)) {
        Write-Host "Configuration file not found at: $configPath" -ForegroundColor Yellow
        Write-Host "Using default configuration values." -ForegroundColor Yellow
        $global:AppConfig = $defaultConfig
        return $global:AppConfig
    }

    try {
        $jsonContent = Get-Content -Path $configPath -Raw -ErrorAction Stop
        $loadedConfig = $jsonContent | ConvertFrom-Json -ErrorAction Stop

        # Convert PSCustomObject to hashtable and merge with defaults
        $config = @{}

        # Copy defaults first
        foreach ($key in $defaultConfig.Keys) {
            $config[$key] = $defaultConfig[$key]
        }

        # Override with loaded values
        foreach ($property in $loadedConfig.PSObject.Properties) {
            $key = $property.Name
            $value = $property.Value

            # Handle nested objects
            if ($value -is [PSCustomObject]) {
                $nestedHashtable = @{}
                foreach ($nestedProp in $value.PSObject.Properties) {
                    $nestedHashtable[$nestedProp.Name] = $nestedProp.Value
                }
                $config[$key] = $nestedHashtable
            } else {
                $config[$key] = $value
            }
        }

        # Validate critical configuration values
        $validationErrors = @()

        if ($config.lookbackDays -lt 1 -or $config.lookbackDays -gt 365) {
            $validationErrors += "lookbackDays must be between 1 and 365"
        }

        if ($config.newAccountThresholdDays -lt 1 -or $config.newAccountThresholdDays -gt 90) {
            $validationErrors += "newAccountThresholdDays must be between 1 and 90"
        }

        if ($config.impossibleTravelSpeedKmh -lt 100 -or $config.impossibleTravelSpeedKmh -gt 5000) {
            $validationErrors += "impossibleTravelSpeedKmh must be between 100 and 5000"
        }

        if ($validationErrors.Count -gt 0) {
            Write-Host "Configuration validation errors:" -ForegroundColor Red
            foreach ($error in $validationErrors) {
                Write-Host "  - $error" -ForegroundColor Red
            }
            Write-Host "Using default configuration values." -ForegroundColor Yellow
            $global:AppConfig = $defaultConfig
            return $global:AppConfig
        }

        Write-Host "Configuration loaded from: $configPath" -ForegroundColor Green
        $global:AppConfig = $config
        return $global:AppConfig
    }
    catch {
        Write-Host "Failed to load configuration: $($_.Exception.Message)" -ForegroundColor Red
        Write-Host "Using default configuration values." -ForegroundColor Yellow
        $global:AppConfig = $defaultConfig
        return $global:AppConfig
    }
}

function Reset-Configuration {
    <#
    .SYNOPSIS
        Resets the cached configuration, forcing a reload on next access.
    #>
    [CmdletBinding()]
    param()

    $global:AppConfig = $null
    Write-Host "Configuration cache cleared." -ForegroundColor Cyan
}

function Get-ConfigValue {
    <#
    .SYNOPSIS
        Gets a specific configuration value by key path.
    .PARAMETER KeyPath
        Dot-separated path to the config value (e.g., "riskLevels.critical")
    .EXAMPLE
        Get-ConfigValue -KeyPath "lookbackDays"
        Get-ConfigValue -KeyPath "riskLevels.critical"
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$KeyPath
    )

    $config = Get-Configuration
    $keys = $KeyPath -split '\.'
    $current = $config

    foreach ($key in $keys) {
        if ($current -is [hashtable] -and $current.ContainsKey($key)) {
            $current = $current[$key]
        }
        elseif ($current -is [PSCustomObject] -and $null -ne $current.$key) {
            $current = $current.$key
        }
        else {
            return $null
        }
    }

    return $current
}

function Test-FirstRunRequired {
    <#
    .SYNOPSIS
        Checks if the first-run setup wizard should be displayed.
    .DESCRIPTION
        Returns $true if firstRunComplete is not set or is $false in settings.json.
    .OUTPUTS
        Boolean indicating if first-run setup is required.
    #>
    [CmdletBinding()]
    param()

    $configPath = Join-Path -Path $PSScriptRoot -ChildPath "..\config\settings.json"

    if (-not (Test-Path $configPath)) {
        return $true
    }

    try {
        $jsonContent = Get-Content -Path $configPath -Raw -ErrorAction Stop
        $loadedConfig = $jsonContent | ConvertFrom-Json -ErrorAction Stop

        if ($null -eq $loadedConfig.firstRunComplete -or $loadedConfig.firstRunComplete -eq $false) {
            return $true
        }

        return $false
    }
    catch {
        return $true
    }
}

function Save-ApiKeyToFile {
    <#
    .SYNOPSIS
        Saves an API key to its local configuration file.
    .PARAMETER ApiName
        The API name (e.g., abuseipdb).
    .PARAMETER ApiKey
        The API key value to save.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateSet("abuseipdb")]
        [string]$ApiName,

        [Parameter(Mandatory)]
        [string]$ApiKey
    )

    $apiFolder = Join-Path -Path $PSScriptRoot -ChildPath "..\api"
    if (-not (Test-Path $apiFolder)) {
        New-Item -ItemType Directory -Path $apiFolder -Force | Out-Null
    }

    $localPath = Join-Path $apiFolder "apikey_${ApiName}_local.ps1"

    $variableName = switch ($ApiName) {
        "abuseipdb" { "ABUSEIPDB_APIKEY" }
    }

    $content = @"
# $ApiName API Key - Auto-generated by setup wizard
# This file is gitignored for security
`$global:$variableName = "$ApiKey"
"@

    $content | Out-File -FilePath $localPath -Encoding UTF8 -Force
    Write-Host "API key saved to: $localPath" -ForegroundColor Green
}

function Update-SettingsJson {
    <#
    .SYNOPSIS
        Updates the settings.json file with new values.
    .PARAMETER Updates
        Hashtable of key-value pairs to update.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [hashtable]$Updates
    )

    $configPath = Join-Path -Path $PSScriptRoot -ChildPath "..\config\settings.json"

    if (-not (Test-Path $configPath)) {
        Write-Host "Settings file not found. Cannot update." -ForegroundColor Red
        return $false
    }

    try {
        $jsonContent = Get-Content -Path $configPath -Raw -ErrorAction Stop
        $config = $jsonContent | ConvertFrom-Json -ErrorAction Stop

        foreach ($key in $Updates.Keys) {
            $parts = $key -split '\.'
            $current = $config

            for ($i = 0; $i -lt $parts.Count - 1; $i++) {
                $part = $parts[$i]
                if ($null -eq $current.$part) {
                    $current | Add-Member -NotePropertyName $part -NotePropertyValue ([PSCustomObject]@{}) -Force
                }
                $current = $current.$part
            }

            $lastPart = $parts[-1]
            if ($current.PSObject.Properties.Name -contains $lastPart) {
                $current.$lastPart = $Updates[$key]
            } else {
                $current | Add-Member -NotePropertyName $lastPart -NotePropertyValue $Updates[$key] -Force
            }
        }

        $config | ConvertTo-Json -Depth 10 | Out-File -FilePath $configPath -Encoding UTF8 -Force
        return $true
    }
    catch {
        Write-Host "Failed to update settings: $($_.Exception.Message)" -ForegroundColor Red
        return $false
    }
}

function Invoke-FirstRunSetup {
    <#
    .SYNOPSIS
        Interactive first-run setup wizard for API key configuration.
    .DESCRIPTION
        Prompts the user to configure optional API keys for AbuseIPDB and OpenAI.
        Saves keys to local files and updates settings.json accordingly.
    .OUTPUTS
        Hashtable containing the updated configuration.
    #>
    [CmdletBinding()]
    param()

    Write-Host ""
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host "   RiskyUserTroubleshooter Setup" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "Welcome! This wizard will help you configure optional features." -ForegroundColor White
    Write-Host "You can skip any feature you don't want to use." -ForegroundColor Gray
    Write-Host ""

    # AbuseIPDB Configuration
    Write-Host "--- AbuseIPDB IP Reputation Checks ---" -ForegroundColor Yellow
    Write-Host "AbuseIPDB provides IP reputation scores to identify malicious IP addresses." -ForegroundColor Gray
    Write-Host "Get a free API key at: https://www.abuseipdb.com/register" -ForegroundColor Gray
    Write-Host ""

    $enableAbuseIpDb = $false
    $abuseIpDbKeyConfigured = $false

    $abuseResponse = Read-Host "Enable AbuseIPDB IP reputation checks? (Y/n)"
    if ($abuseResponse -eq "" -or $abuseResponse -match "^[Yy]") {
        $enableAbuseIpDb = $true
        $abuseKey = Read-Host "Enter your AbuseIPDB API key (or press Enter to skip)"

        if (-not [string]::IsNullOrWhiteSpace($abuseKey) -and $abuseKey -ne "your-api-key-here") {
            Save-ApiKeyToFile -ApiName "abuseipdb" -ApiKey $abuseKey
            $abuseIpDbKeyConfigured = $true
            Write-Host "AbuseIPDB API key configured successfully." -ForegroundColor Green
        } else {
            Write-Host "No API key provided. AbuseIPDB checks will be skipped." -ForegroundColor Yellow
            $enableAbuseIpDb = $false
        }
    } else {
        Write-Host "AbuseIPDB checks disabled." -ForegroundColor Gray
    }

    Write-Host ""

    # Update settings.json
    $updates = @{
        "firstRunComplete"           = $true
        "apiKeys.abuseipdb.enabled"  = $enableAbuseIpDb
        "apiKeys.abuseipdb.keyConfigured" = $abuseIpDbKeyConfigured
    }

    if (Update-SettingsJson -Updates $updates) {
        Write-Host "Configuration saved successfully." -ForegroundColor Green
    } else {
        Write-Host "Warning: Could not save configuration. Settings may not persist." -ForegroundColor Yellow
    }

    Write-Host ""
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host "   Setup Complete!" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host ""

    # Summary
    Write-Host "Configuration Summary:" -ForegroundColor White
    Write-Host "  AbuseIPDB: $(if ($enableAbuseIpDb -and $abuseIpDbKeyConfigured) { 'Enabled' } else { 'Disabled' })" -ForegroundColor $(if ($enableAbuseIpDb -and $abuseIpDbKeyConfigured) { 'Green' } else { 'Gray' })
    Write-Host ""
    Write-Host "You can re-run setup by setting 'firstRunComplete' to false in config/settings.json" -ForegroundColor Gray
    Write-Host ""

    # Clear cached config and reload
    Reset-Configuration
    return Get-Configuration
}
