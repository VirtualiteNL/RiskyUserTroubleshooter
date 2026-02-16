<#
.SYNOPSIS
    Microsoft 365 Risky User Troubleshooter

.DESCRIPTION
    This script connects to Microsoft 365 (via Graph API and Exchange Online),
    collects data on a risky user. The output is a Fluent UI-style HTML dashboard
    with popups, summaries, and optional AI-generated advisory.

.AUTHOR
    Danny Vorst (@Virtualite.nl)
    https://virtualite.nl | https://github.com/VirtualiteNL

.LICENSE
    Microsoft 365 Risky User Troubleshooter - Copyright & License

    This script is developed and maintained by Danny Vorst (Virtualite.nl).
    It is licensed for **non-commercial use only**.

    Allowed:
    - Free to use internally for reporting, monitoring, or educational purposes
    - Forks or modifications are allowed **only if published publicly** (e.g., on GitHub)
    - Author name, styling, logo and script headers must remain unchanged

    Not allowed:
    - Commercial use, resale, or integration in closed-source tooling
    - Removing Virtualite branding, layout, or author headers

    By using this script, you agree to the license terms.
    Violations may result in takedown notices, DMCA reports, or legal action.

    Also licensed under Creative Commons BY-NC-SA 4.0 where compatible.
    See LICENSE.md for full terms.
#>

#region Input Validation

function Test-ValidUpnFormat {
    <#
    .SYNOPSIS
        Validates UPN format using regex.
    #>
    param([string]$Upn)
    return $Upn -match '^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
}

function Reset-GlobalState {
    <#
    .SYNOPSIS
        Resets all global variables between user processing to prevent data leakage.
    #>
    $global:aiadvisory = @{
        UserRisk   = @()
        SignInRisk = @()
        CA         = @()
        Summary    = @{}
        Advisory   = ""
    }
    $global:AbuseIpCache = @{}
    $global:UserDirectoryAuditLogs = @()
    $global:userRoles = @()

    Write-Log -Type "Information" -Message "Global state reset for new user processing"
}

# Prompt for one or more UPNs (comma-separated)
$userInput = Read-Host "Enter one or more UPNs to investigate (comma-separated)"
if ([string]::IsNullOrWhiteSpace($userInput)) {
    Write-Host "At least one UPN is required. Exiting..." -ForegroundColor Red
    exit 1
}

# Split input into individual UPNs and validate format
$upnList = $userInput -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne "" }

# Validate UPN formats
$invalidUpns = @()
$validUpns = @()
foreach ($upn in $upnList) {
    if (Test-ValidUpnFormat -Upn $upn) {
        $validUpns += $upn
    } else {
        $invalidUpns += $upn
    }
}

if ($invalidUpns.Count -gt 0) {
    Write-Host "Invalid UPN format detected:" -ForegroundColor Yellow
    foreach ($invalid in $invalidUpns) {
        Write-Host "  - $invalid" -ForegroundColor Yellow
    }
    if ($validUpns.Count -eq 0) {
        Write-Host "No valid UPNs provided. Exiting..." -ForegroundColor Red
        exit 1
    }
    Write-Host "Continuing with valid UPNs only..." -ForegroundColor Cyan
}

$upnList = $validUpns

#endregion

#region Initialization

# Load logger module first so logging is available immediately
. "$PSScriptRoot\modules\logger.ps1"

# Create folders and define paths
$logFolder    = Join-Path $PSScriptRoot "logs"
$reportFolder = Join-Path $PSScriptRoot "reports"
$exportFolder = Join-Path $PSScriptRoot "exports"
$global:jsonExportFolder = Join-Path $PSScriptRoot "exports"

if (-not (Test-Path $logFolder))    { New-Item -ItemType Directory -Path $logFolder    | Out-Null }
if (-not (Test-Path $reportFolder)) { New-Item -ItemType Directory -Path $reportFolder | Out-Null }
if (-not (Test-Path $exportFolder)) { New-Item -ItemType Directory -Path $exportFolder | Out-Null }

# Load configuration module
. "$PSScriptRoot\modules\config.ps1"

# Check if first-run setup is required
if (Test-FirstRunRequired) {
    Write-Host ""
    Write-Host "First-time setup detected. Starting configuration wizard..." -ForegroundColor Yellow
    $config = Invoke-FirstRunSetup
} else {
    $config = Get-Configuration
}

# Load all custom modules ONCE (outside the loop for performance)
. "$PSScriptRoot\modules\requirements.ps1"
. "$PSScriptRoot\modules\htmltools.ps1"
. "$PSScriptRoot\modules\abuseipdb.ps1"
. "$PSScriptRoot\modules\htmlbuilder.ps1"
. "$PSScriptRoot\modules\userrisk.ps1"
. "$PSScriptRoot\modules\signinrisk.ps1"
. "$PSScriptRoot\modules\export-capolicies.ps1"
. "$PSScriptRoot\modules\exportreportdata.ps1"
. "$PSScriptRoot\modules\cleanup.ps1"

# Check required modules and load API keys
Ensure-RequiredModules

# Connect to Microsoft 365
. "$PSScriptRoot\modules\connect.ps1"
Connect-GraphAndExchange
Write-Host "Connected to Microsoft 365" -ForegroundColor Green

#endregion

#region Main Processing Loop

# Track errors for summary
$processedUsers = @()
$failedUsers = @()
$totalUsers = $upnList.Count
$currentUserIndex = 0

foreach ($upn in $upnList) {
    $currentUserIndex++

    # Progress indicator
    $progressPercent = [math]::Round(($currentUserIndex / $totalUsers) * 100)
    Write-Host "`n[$currentUserIndex/$totalUsers] ($progressPercent%) Processing: $upn" -ForegroundColor Cyan
    Write-Progress -Activity "Processing Users" -Status "User $currentUserIndex of $totalUsers" -PercentComplete $progressPercent -CurrentOperation $upn

    # Reset global state for each user
    Reset-GlobalState

    # Sanitize the current UPN for use in file names
    $sanitizedUpn = $upn -replace '[^a-zA-Z0-9@._-]', '_'

    # Define log and report paths for this user
    $logPath      = Join-Path $logFolder    "incidentreport-$sanitizedUpn.txt"
    $reportPath   = Join-Path $reportFolder "incidentreport-$sanitizedUpn.html"

    Write-Host "   Log path:    $logPath"
    Write-Host "   Report path: $reportPath"

    # Start log
    Start-Log -Path $logPath
    Write-Log -Type "Information" -Message "Incident scan started for: $upn"
    Write-Host "Starting incident investigation..." -ForegroundColor Cyan

    Write-Log -Type "Information" -Message "Log folder: $logFolder"
    Write-Log -Type "Information" -Message "Report folder: $reportFolder"
    Write-Log -Type "Information" -Message "Log path: $logPath"
    Write-Log -Type "Information" -Message "Report path: $reportPath"

    try {
        # Collect data
        Write-Host "Loading and executing UserRisk IOC modules..." -ForegroundColor DarkCyan
        $userRiskContent = Get-UserRiskSection -LogPath $logPath -UPN $upn

        Write-Host "Loading and executing SignInRisk IOC modules..." -ForegroundColor DarkCyan
        $signinRiskContent = Get-SignInRiskSection -LogPath $logPath -UPN $upn

        Export-CAPolicies

        # Export to JSON
        $exportedJsonPath = Export-ReportDataToJson -ExportPath $reportFolder -UPN $upn
        Write-Log -Type "OK" -Message "Exported report data to: $exportedJsonPath"

        # Generate risk summary
        Write-Host "Generating risk summary..." -ForegroundColor DarkCyan
        Write-Log -Type "Information" -Message "Generating automated risk summary"

        # Assemble HTML report
        $Sections = @()
        $Sections += New-RiskSummary

        $Sections += $userRiskContent
        $Sections += $signinRiskContent

        Build-IncidentReport -Sections $Sections -OutputPath $reportPath -UserPrincipalName $upn
        Write-Host "Investigation finished. Report ready for review." -ForegroundColor Green
        Write-Log -Type "OK" -Message "Investigation finished. Report ready for review."

        $processedUsers += @{
            UPN        = $upn
            ReportPath = $reportPath
            Status     = "Success"
        }

        # Cleanup temporary exports for this user
        if ($exportedJsonPath) {
            Invoke-PostReportCleanup -JsonPath $exportedJsonPath
        }
    }
    catch {
        $errorMessage = $_.Exception.Message
        Write-Log -Type "Error" -Message "Fatal error processing $upn`: $errorMessage"
        Write-Host "Failed to process $upn. Check log file for details." -ForegroundColor Red
        Write-Host "Error: $errorMessage" -ForegroundColor Red

        $failedUsers += @{
            UPN   = $upn
            Error = $errorMessage
        }

        # Continue with next user instead of stopping
        continue
    }
}

Write-Progress -Activity "Processing Users" -Completed

#endregion

#region Cleanup and Summary

# Disconnect services
try {
    Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null
    Write-Log -Type "Information" -Message "Disconnected from Microsoft Graph."
} catch {
    Write-Log -Type "Alert" -Message "Failed to disconnect from Microsoft Graph: $($_.Exception.Message)"
}

try {
    Disconnect-ExchangeOnline -Confirm:$false -ErrorAction SilentlyContinue | Out-Null
    Write-Log -Type "Information" -Message "Disconnected from Exchange Online."
} catch {
    Write-Log -Type "Alert" -Message "Failed to disconnect from Exchange Online: $($_.Exception.Message)"
}

# Cleanup export folder
Invoke-PostReportCleanup -JsonPath $exportFolder
Write-Log -Type "Information" -Message "Temporary exports cleaned up."

# Print summary
Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "          PROCESSING SUMMARY" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Total users processed: $totalUsers" -ForegroundColor White
Write-Host "Successful: $($processedUsers.Count)" -ForegroundColor Green
Write-Host "Failed: $($failedUsers.Count)" -ForegroundColor $(if ($failedUsers.Count -gt 0) { "Red" } else { "Green" })

if ($processedUsers.Count -gt 0) {
    Write-Host "`nSuccessful Reports:" -ForegroundColor Green
    foreach ($user in $processedUsers) {
        Write-Host "  $($user.UPN) -> $($user.ReportPath)" -ForegroundColor Gray
    }
}

if ($failedUsers.Count -gt 0) {
    Write-Host "`nFailed Users:" -ForegroundColor Red
    foreach ($user in $failedUsers) {
        Write-Host "  $($user.UPN): $($user.Error)" -ForegroundColor Red
    }
}

Write-Host "`n========================================" -ForegroundColor Cyan

#endregion
