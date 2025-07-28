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
function Invoke-PostReportCleanup {
    param (
        [Parameter(Mandatory = $true)]
        [string]$JsonPath  # 📦 Path to a JSON file OR to the export folder
    )

    # 📂 Determine actual folder to clean
    $folderPath = if (Test-Path $JsonPath -PathType Leaf) {
        # If it's a file, clean its folder
        Split-Path $JsonPath -Parent
    } elseif (Test-Path $JsonPath -PathType Container) {
        # If it's already a folder, use it
        $JsonPath
    } else {
        Write-Log -Type "Error" -Message "❌ Invalid path provided to cleanup: $JsonPath"
        return
    }

    # 🧹 Get all .json files in the folder
    $jsonFiles = Get-ChildItem -Path $folderPath -Filter "*.json" -File

    foreach ($file in $jsonFiles) {
        try {
            Remove-Item $file.FullName -Force
            Write-Log -Type "Information" -Message "🗑️ Deleted JSON file: $($file.Name)"
        } catch {
            Write-Log -Type "Error" -Message "❌ Failed to delete JSON file ${file.Name}: $($_.Exception.Message)"
        }
    }

    Write-Log -Type "Information" -Message "✅ JSON cleanup completed in folder: $folderPath"
}