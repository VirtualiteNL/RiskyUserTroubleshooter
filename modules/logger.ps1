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
# 🌍 Global variable used to store the current log file path
$Global:LogFilePath = ""

function Start-Log {
    <#
    .SYNOPSIS
        📂 Initializes the logging mechanism by creating a fresh log file.
    .DESCRIPTION
        This function sets the global path for logging and ensures that any existing file is removed.
        It is typically called at the beginning of a script to start a clean session log.
    #>
    param (
        [string]$Path
    )

    $Global:LogFilePath = $Path

    # 🗑️ Remove any existing file at the path to ensure a clean start
    if (Test-Path $Path) {
        Remove-Item $Path -Force
    }

    # 📄 Create a new log file to capture subsequent entries
    New-Item -Path $Path -ItemType File -Force | Out-Null
}

function Write-Log {
    <#
    .SYNOPSIS
        🖊️ Writes a timestamped log entry to the configured log file.
    .DESCRIPTION
        Appends a structured log line with a severity type to the current session log file.
        Supported types are: Alert, OK, Information, and Error.
    .PARAMETER Type
        The category or severity of the log entry.
    .PARAMETER Message
        The textual message to record in the log.
    #>
    param (
        [ValidateSet("Alert", "OK", "Information", "Error")]
        [string]$Type,

        [string]$Message
    )

    # 🕒 Get current timestamp in standard format
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"

    # 🧾 Format the log line consistently
    $line = "[{0}] [{1}] {2}" -f $timestamp, $Type.ToUpper(), $Message

    # 📝 Append the log line to the file
    Add-Content -Path $Global:LogFilePath -Value $line
}