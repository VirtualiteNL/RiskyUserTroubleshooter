<#
.SYNOPSIS
    Microsoft 365 Risky User Troubleshooter - Logging Module

.DESCRIPTION
    Provides structured logging with configurable log levels,
    optional JSON output format, and console/file output.

.AUTHOR
    Danny Vorst (@Virtualite.nl)
    https://virtualite.nl | https://github.com/VirtualiteNL

.LICENSE
    Microsoft 365 Risky User Troubleshooter - Copyright & License
    Licensed for non-commercial use only.
    See LICENSE.md for full terms.
#>

# Global variables for logging
$Global:LogFilePath = ""
$Global:LogLevel = "Information"  # Debug, Information, Alert, OK, Error
$Global:EnableDebugLogging = $false
$Global:EnableJsonLogging = $false

# Log level hierarchy (lower number = more verbose)
$script:LogLevelOrder = @{
    "Debug"       = 0
    "Information" = 1
    "OK"          = 2
    "Alert"       = 3
    "Error"       = 4
}

function Set-LogConfiguration {
    <#
    .SYNOPSIS
        Configures logging settings.
    .PARAMETER Level
        Minimum log level to record. Options: Debug, Information, OK, Alert, Error
    .PARAMETER EnableDebug
        If true, enables debug-level logging.
    .PARAMETER EnableJson
        If true, outputs logs in JSON format.
    #>
    [CmdletBinding()]
    param(
        [ValidateSet("Debug", "Information", "OK", "Alert", "Error")]
        [string]$Level = "Information",

        [switch]$EnableDebug,
        [switch]$EnableJson
    )

    $Global:LogLevel = $Level
    $Global:EnableDebugLogging = $EnableDebug.IsPresent
    $Global:EnableJsonLogging = $EnableJson.IsPresent

    if ($EnableDebug) {
        $Global:LogLevel = "Debug"
    }

    Write-Host "Logging configured: Level=$($Global:LogLevel), Debug=$($Global:EnableDebugLogging), JSON=$($Global:EnableJsonLogging)" -ForegroundColor Cyan
}

function Start-Log {
    <#
    .SYNOPSIS
        Initializes the logging mechanism by creating a fresh log file.
    .DESCRIPTION
        This function sets the global path for logging and ensures that any existing file is removed.
        It is typically called at the beginning of a script to start a clean session log.
    .PARAMETER Path
        The full path to the new log file to create.
    .PARAMETER Append
        If specified, appends to existing log file instead of replacing.
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string]$Path,

        [switch]$Append
    )

    $Global:LogFilePath = $Path

    # Remove existing file if not appending
    if (-not $Append -and (Test-Path $Path)) {
        Remove-Item $Path -Force
    }

    # Create file if it doesn't exist
    if (-not (Test-Path $Path)) {
        New-Item -Path $Path -ItemType File -Force | Out-Null
    }

    # Write header
    $header = if ($Global:EnableJsonLogging) {
        @{
            LogStart    = (Get-Date -Format "o")
            LogPath     = $Path
            LogLevel    = $Global:LogLevel
            DebugMode   = $Global:EnableDebugLogging
            Hostname    = $env:COMPUTERNAME
            User        = $env:USERNAME
        } | ConvertTo-Json -Compress
    } else {
        "========================================`n" +
        "Log started: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')`n" +
        "Log path: $Path`n" +
        "Log level: $($Global:LogLevel)`n" +
        "========================================`n"
    }

    Add-Content -Path $Path -Value $header

    Write-Host "Log started at: $Path" -ForegroundColor Cyan
}

function Write-Log {
    <#
    .SYNOPSIS
        Writes a timestamped log entry to the configured log file.
    .DESCRIPTION
        Appends a structured log line with a severity type to the current session log file.
        Supported types are: Alert, OK, Information, Error, Debug.
        Log entries below the configured log level are filtered out.
    .PARAMETER Type
        The category or severity of the log entry.
    .PARAMETER Message
        The textual message to record in the log.
    .PARAMETER Data
        Optional additional data to include (for JSON logging).
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [ValidateSet("Alert", "OK", "Information", "Error", "Debug")]
        [string]$Type,

        [Parameter(Mandatory)]
        [string]$Message,

        [hashtable]$Data
    )

    # Check if this log level should be recorded
    $currentLevelOrder = $script:LogLevelOrder[$Global:LogLevel]
    $messageLevelOrder = $script:LogLevelOrder[$Type]

    if ($messageLevelOrder -lt $currentLevelOrder) {
        return  # Skip this message
    }

    # Skip debug messages if debug logging is disabled
    if ($Type -eq "Debug" -and -not $Global:EnableDebugLogging) {
        return
    }

    # Bail if no log path configured
    if ([string]::IsNullOrWhiteSpace($Global:LogFilePath)) {
        return
    }

    # Get current timestamp
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"

    if ($Global:EnableJsonLogging) {
        # JSON format
        $logEntry = @{
            Timestamp = $timestamp
            Level     = $Type.ToUpper()
            Message   = $Message
        }

        if ($Data) {
            $logEntry.Data = $Data
        }

        $line = $logEntry | ConvertTo-Json -Compress
    } else {
        # Plain text format
        $line = "[{0}] [{1,-11}] {2}" -f $timestamp, $Type.ToUpper(), $Message
    }

    # Append to log file
    Add-Content -Path $Global:LogFilePath -Value $line
}

function Write-LogSection {
    <#
    .SYNOPSIS
        Writes a section header to the log for better organization.
    .PARAMETER Title
        The title of the section.
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string]$Title
    )

    if ($Global:EnableJsonLogging) {
        Write-Log -Type "Information" -Message "=== SECTION: $Title ===" -Data @{ SectionStart = $Title }
    } else {
        $separator = "=" * 50
        Write-Log -Type "Information" -Message "`n$separator"
        Write-Log -Type "Information" -Message "  $Title"
        Write-Log -Type "Information" -Message "$separator"
    }
}

function Write-LogError {
    <#
    .SYNOPSIS
        Writes an error to the log with exception details.
    .PARAMETER Message
        The error message.
    .PARAMETER Exception
        The exception object (optional).
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string]$Message,

        [System.Exception]$Exception
    )

    $data = @{}
    if ($Exception) {
        $data = @{
            ExceptionType    = $Exception.GetType().FullName
            ExceptionMessage = $Exception.Message
            StackTrace       = $Exception.StackTrace
        }
    }

    Write-Log -Type "Error" -Message $Message -Data $data
}

function Get-LogSummary {
    <#
    .SYNOPSIS
        Generates a summary of log entries by type.
    .OUTPUTS
        Hashtable with counts per log level.
    #>
    [CmdletBinding()]
    param()

    if (-not (Test-Path $Global:LogFilePath)) {
        return @{}
    }

    $content = Get-Content -Path $Global:LogFilePath -Raw

    $summary = @{
        Debug       = ([regex]::Matches($content, '\[DEBUG\]')).Count
        Information = ([regex]::Matches($content, '\[INFORMATION\]')).Count
        OK          = ([regex]::Matches($content, '\[OK\]')).Count
        Alert       = ([regex]::Matches($content, '\[ALERT\]')).Count
        Error       = ([regex]::Matches($content, '\[ERROR\]')).Count
    }

    return $summary
}

function Stop-Log {
    <#
    .SYNOPSIS
        Finalizes the log with a summary and closing entry.
    #>
    [CmdletBinding()]
    param()

    $summary = Get-LogSummary

    Write-LogSection -Title "LOG SUMMARY"
    Write-Log -Type "Information" -Message "Errors: $($summary.Error)"
    Write-Log -Type "Information" -Message "Alerts: $($summary.Alert)"
    Write-Log -Type "Information" -Message "OK: $($summary.OK)"
    Write-Log -Type "Information" -Message "Info: $($summary.Information)"
    Write-Log -Type "Information" -Message "Debug: $($summary.Debug)"

    $footer = if ($Global:EnableJsonLogging) {
        @{
            LogEnd  = (Get-Date -Format "o")
            Summary = $summary
        } | ConvertTo-Json -Compress
    } else {
        "`n========================================`n" +
        "Log ended: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')`n" +
        "========================================"
    }

    Add-Content -Path $Global:LogFilePath -Value $footer
}
