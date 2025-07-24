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
# 📁 Check all required powershell modules and install if missing
. "$PSScriptRoot\modules\requirements.ps1"
Ensure-RequiredModules

# 🔹 Prompt the analyst for the UPN (User Principal Name) of the account under investigation
$upn = Read-Host "Enter UPN of the user to investigate"
if ([string]::IsNullOrWhiteSpace($upn)) {
    # Abort if UPN is empty or invalid
    Write-Host "UPN is required. Exiting..." -ForegroundColor Red
    Write-Log -Type "Information" -Message "[Runner] Received UPN input: $upn"
    exit 1
}

# 📁 Import all required custom modules (utility, reporting, data collectors, API integration)
. "$PSScriptRoot\modules\htmltools.ps1"
. "$PSScriptRoot\modules\connect.ps1"
. "$PSScriptRoot\modules\logger.ps1"
. "$PSScriptRoot\modules\abuseipdb.ps1"
. "$PSScriptRoot\modules\htmlbuilder.ps1"
. "$PSScriptRoot\modules\userrisk.ps1"
. "$PSScriptRoot\modules\signinrisk.ps1"
. "$PSScriptRoot\modules\export-capolicies.ps1"
. "$PSScriptRoot\modules\exportreportdata.ps1"
. "$PSScriptRoot\modules\openaiadvisory.ps1"
. "$PSScriptRoot\modules\cleanup.ps1"

# 📂 Create required folder structure
$sanitizedUpn = $upn -replace '[^a-zA-Z0-9@._-]', '_'
$logFolder    = Join-Path $PSScriptRoot "logs"
$reportFolder = Join-Path $PSScriptRoot "reports"
$exportFolder = Join-Path $PSScriptRoot "exports"
$global:jsonExportFolder = Join-Path $PSScriptRoot "exports"

# ✉️ Ensure the output folders exist
if (-not (Test-Path $logFolder))    { New-Item -ItemType Directory -Path $logFolder    | Out-Null }
if (-not (Test-Path $reportFolder)) { New-Item -ItemType Directory -Path $reportFolder | Out-Null }
if (-not (Test-Path $exportFolder)) { New-Item -ItemType Directory -Path $exportFolder | Out-Null }


# 🧠 Initialize advisory object
$global:aiadvisory = @{
    UserRisk   = @()
    SignInRisk = @()
    CA         = @()
    Summary    = @{ }
    Advisory   = ""
}


# 📃 Define the full file paths for the report and corresponding log
$logPath    = Join-Path $logFolder    "incidentreport-$sanitizedUpn.txt"
$reportPath = Join-Path $reportFolder "incidentreport-$sanitizedUpn.html"

# 📑 Begin writing log to file
Start-Log -Path $logPath
Write-Log -Type "Information" -Message "Incident scan started."

Write-Log -Type "Information" -Message "[Runner] Initialized log folder: $logFolder"
Write-Log -Type "Information" -Message "[Runner] Initialized report folder: $reportFolder"
Write-Log -Type "Information" -Message "[Runner] Log path: $logPath"
Write-Log -Type "Information" -Message "[Runner] Report path: $reportPath"

try {
    # 🔗 Establish connections to Microsoft Graph and Exchange Online
    Connect-GraphAndExchange
    Write-Log -Type "Information" -Message "Connected to Microsoft Graph and Exchange."

    # 🧋 Collect both user-based and sign-in-based risk assessments (HTML format)
$userRiskContent   = Get-UserRiskSection -LogPath $logPath -UPN $upn
$signinRiskContent = Get-SignInRiskSection -LogPath $logPath -UPN $upn
    # 🔐 Export Conditional Access policies (needed for AI analysis)
        Export-CAPolicies

    # 📤 Export collected report data as JSON for reuse (e.g. AI advisory)
    $exportedJsonPath = Export-ReportDataToJson -ExportPath $reportFolder -UPN $upn
    Write-Log -Type "Information" -Message "Exported report data to: $exportedJsonPath"

    # 🤖 Generate AI-powered advisory and risk summary
    Invoke-OpenAIAdvisory

    # 📌 Assemble HTML report sections
    $Sections = @()

# 📌 Assemble HTML report sections
$Sections = @()

# ⛰ Add AI advisory section if available
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

# 📆 Append other report sections
$Sections += $userRiskContent
$Sections += $signinRiskContent

    Build-IncidentReport -Sections $Sections -OutputPath $reportPath -UserPrincipalName $upn
    Write-Log -Type "Information" -Message "Report generated successfully."

    # 🔌 Disconnect sessions cleanly after data collection
    Disconnect-MgGraph | Out-Null
    Write-Log -Type "Information" -Message "Disconnected from Microsoft Graph."

    Disconnect-ExchangeOnline -Confirm:$false | Out-Null
    Write-Log -Type "Information" -Message "Disconnected from Exchange Online."

    # 🧹 POST-REPORT CLEANUP – Delete only this session's exported JSON files
    Invoke-PostReportCleanup -JsonPath $exportedJsonPath
    Invoke-PostReportCleanup -JsonPath $exportFolder

}

catch {
    # ⚠️ Catch any fatal errors and log for investigation
    Write-Log -Type "Error" -Message "Fatal error: $_"
}