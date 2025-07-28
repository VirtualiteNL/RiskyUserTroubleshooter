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
function Export-ReportDataToJson {
    param (
        [string]$ExportPath = "$PSScriptRoot\..\exports",  # 📂 Default export folder
        [string]$UPN                                         # 👤 User principal name (sanitized in filename)
    )

    # 🚫 Abort if the advisory object is not in memory
    if (-not $global:aiadvisory) {
        Write-Log -Type "Error" -Message "❌ No ReportData found in memory. Export aborted."
        return
    }

    # 📁 Ensure the export folder exists (create if missing)
    if (-not (Test-Path $ExportPath)) {
        Write-Log -Type "Information" -Message "📁 Creating export folder: $ExportPath"
        New-Item -Path $ExportPath -ItemType Directory | Out-Null
    }

    # 🕒 Timestamp for unique filenames
    $timestamp = Get-Date -Format "yyyyMMdd-HHmmss"

    # 🔐 Sanitize UPN to avoid invalid filename characters
    $safeUpn = $UPN -replace '[^\w\.-]', '_'

    # 📝 Final JSON filename: reportdata-<user>-<timestamp>.json
    $fileName = "$ExportPath\reportdata-$safeUpn-$timestamp.json"

    try {
        # 💾 Convert advisory object to JSON and write to disk
        $global:aiadvisory | ConvertTo-Json -Depth 6 | Out-File -FilePath $fileName -Encoding UTF8
        Write-Log -Type "Information" -Message "💾 Exported report data to: $fileName"
    }
    catch {
        # ❗ Log any export failure
        Write-Log -Type "Error" -Message "❌ Failed to export report data: $($_.Exception.Message)"
    }

    # 📤 Return the generated filename to caller
    return $fileName
}