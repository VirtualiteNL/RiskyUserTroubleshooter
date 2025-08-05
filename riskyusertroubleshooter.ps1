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
# 🔹 Prompt the analyst for the UPN (User Principal Name) of the account under investigation
# 🔹 Prompt for one or more UPNs (comma-separated only)
$userInput = Read-Host "Enter one or more UPNs to investigate (comma-separated)"
if ([string]::IsNullOrWhiteSpace($userInput)) {
    Write-Host "❌ At least one UPN is required. Exiting..." -ForegroundColor Red
    exit 1
}

# 🔹 Split input into individual UPNs
$upnList = $userInput -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne "" }

# 📁 Load logger module first so logging is available immediately
. "$PSScriptRoot\modules\logger.ps1"

# 📂 Create folders and define paths
$logFolder    = Join-Path $PSScriptRoot "logs"
$reportFolder = Join-Path $PSScriptRoot "reports"
$exportFolder = Join-Path $PSScriptRoot "exports"
$global:jsonExportFolder = Join-Path $PSScriptRoot "exports"

if (-not (Test-Path $logFolder))    { New-Item -ItemType Directory -Path $logFolder    | Out-Null }
if (-not (Test-Path $reportFolder)) { New-Item -ItemType Directory -Path $reportFolder | Out-Null }
if (-not (Test-Path $exportFolder)) { New-Item -ItemType Directory -Path $exportFolder | Out-Null }

    # 🔗 Connect to Microsoft 365
    . "$PSScriptRoot\modules\connect.ps1"

    Connect-GraphAndExchange
    Write-Host "🔗 Connected to Microsoft 365" -ForegroundColor Green

foreach ($upn in $upnList) {
    # Sanitize the current UPN for use in file names
    $sanitizedUpn = $upn -replace '[^a-zA-Z0-9@._-]', '_'

    # Define log and report paths for this user
    $logPath      = Join-Path $logFolder    "incidentreport-$sanitizedUpn.txt"
    $reportPath   = Join-Path $reportFolder "incidentreport-$sanitizedUpn.html"

    # Example usage
    Write-Host "▶️ Processing $upn..."
    Write-Host "   Log path:    $logPath"
    Write-Host "   Report path: $reportPath"
    

# 📑 Start log
Start-Log -Path $logPath
Write-Log -Type "Information" -Message "📊 Incident scan started."
Write-Host "📊 Starting incident investigation..." -ForegroundColor Cyan

# 📁 Check required modules
. "$PSScriptRoot\modules\requirements.ps1"
Ensure-RequiredModules

# 📦 Load all custom modules
. "$PSScriptRoot\modules\htmltools.ps1"
. "$PSScriptRoot\modules\abuseipdb.ps1"
. "$PSScriptRoot\modules\htmlbuilder.ps1"
. "$PSScriptRoot\modules\userrisk.ps1"
. "$PSScriptRoot\modules\signinrisk.ps1"
. "$PSScriptRoot\modules\export-capolicies.ps1"
. "$PSScriptRoot\modules\exportreportdata.ps1"
. "$PSScriptRoot\modules\openaiadvisory.ps1"
. "$PSScriptRoot\modules\cleanup.ps1"

# 🧠 Initialize advisory object
$global:aiadvisory = @{
    UserRisk   = @()
    SignInRisk = @()
    CA         = @()
    Summary    = @{ }
    Advisory   = ""
}

Write-Log -Type "Information" -Message "📁 Log folder: $logFolder"
Write-Log -Type "Information" -Message "📁 Report folder: $reportFolder"
Write-Log -Type "Information" -Message "📄 Log path: $logPath"
Write-Log -Type "Information" -Message "📄 Report path: $reportPath"

try {
    # 📥 Collect data
    Write-Host "📦 Loading and executing UserRisk IOC modules..." -ForegroundColor DarkCyan
    $userRiskContent   = Get-UserRiskSection -LogPath $logPath -UPN $upn
    Write-Host "📦 Loading and executing SignInRisk IOC modules..." -ForegroundColor DarkCyan
    $signinRiskContent = Get-SignInRiskSection -LogPath $logPath -UPN $upn

    Export-CAPolicies

    # 📤 Export to JSON
    $exportedJsonPath = Export-ReportDataToJson -ExportPath $reportFolder -UPN $upn
    Write-Log -Type "OK" -Message "📤 Exported report data to: $exportedJsonPath"

    # 🤖 Advisory
    Invoke-OpenAIAdvisory

    # 🧱 Assemble HTML report
    $Sections = @()
    if ($global:aiadvisory.Advisory) {
        $Sections += Convert-AdvisoryToHtml -Text $global:aiadvisory.Advisory
    } else {
        $Sections += @"
<div class='warning'>
  <h4>⚠️ OpenAI Advisory Skipped</h4>
  <p>
    The OpenAI API key was not configured.<br>
    No AI-based risk analysis or summary was included in this report.<br>
    Risk indicators for user and sign-ins are still available in the other tabs.
  </p>
</div>
"@
    }

    $Sections += $userRiskContent
    $Sections += $signinRiskContent

    Build-IncidentReport -Sections $Sections -OutputPath $reportPath -UserPrincipalName $upn
    Write-Host "🏁 Investigation finished. Report ready for review." -ForegroundColor Green
    Write-Log  -Type "OK" -Message "🏁 Investigation finished. Report ready for review."
}
catch {
    Write-Log -Type "Error" -Message "❌ Fatal error: $($_.Exception.Message)"
    Write-Host "❌ Script failed. Check log file for details." -ForegroundColor Red
}
}
    # 🔌 Disconnect services
    Disconnect-MgGraph | Out-Null
    Write-Log -Type "Information" -Message "🔌 Disconnected from Microsoft Graph."

    Disconnect-ExchangeOnline -Confirm:$false | Out-Null
    Write-Log -Type "Information" -Message "🔌 Disconnected from Exchange Online."

    # 🧹 Cleanup
    Invoke-PostReportCleanup -JsonPath $exportedJsonPath
    Invoke-PostReportCleanup -JsonPath $exportFolder
    Write-Log -Type "Information" -Message "🧹 Temporary exports cleaned up."