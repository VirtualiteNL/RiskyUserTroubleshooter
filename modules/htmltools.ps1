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
function Convert-ToHtmlTable {
    param (
        [Parameter(Mandatory = $true)]
        [array]$Data
    )

    # 🧪 Return placeholder text if the data array is empty or null
    if (-not $Data -or $Data.Count -eq 0) {
        return "<p><i>No data available.</i></p>"
    }

    # 📋 Initialize the HTML table
    $html = "<table><thead><tr>"

    # 🧭 Extract column names in defined order from the first object
    $firstRow = $Data | Select-Object -First 1
    $columns = $firstRow.PSObject.Properties.Name

    # 🏷️ Render the table header using the column names
    foreach ($col in $columns) {
        $html += "<th>$col</th>"
    }

    $html += "</tr></thead><tbody>"

    # 📊 Render each row of data, preserving the column order
    foreach ($row in $Data) {
        $html += "<tr>"
        foreach ($col in $columns) {
            $value = $row.$col
            $html += "<td>$value</td>"
        }
        $html += "</tr>"
    }

    $html += "</tbody></table>"

    # ✅ Return the final HTML table as a string
    return $html
}
function Convert-AdvisoryToHtml {
    param (
        [string]$Text
    )

    # 🧪 Exit early if input is empty
    if (-not $Text -or $Text.Trim() -eq '') {
        Write-Log -Type "Alert" -Message "⚠️ Advisory text is empty."
        return "<p>No advisory text available.</p>"
    }

    # 📦 Define known advisory sections (emoji key used for detection only)
    $sections = @{
        "📊" = @{ Title = "Overall Risk Score";        Content = "" }
        "📋" = @{ Title = "Overall Risk Assessment";   Content = "" }
        "🎯" = @{ Title = "Attack Profile Summary";    Content = "" }
        "🔧" = @{ Title = "Recommended Actions";       Content = "" }
        "🧱" = @{ Title = "Conditional Access Policy Evaluation"; Content = "" }
    }

    # 🔍 Parse each line and associate with correct section
    $lines = $Text -split "(?ms)\r?\n|\\n"
    $currentKey = ""

    foreach ($line in $lines) {
        $trimmed = $line.Trim()
        if ($trimmed.Length -ge 2 -and $sections.ContainsKey($trimmed.Substring(0,2))) {
            $currentKey = $trimmed.Substring(0,2)
            continue
        }
        if ($currentKey) {
            $sections[$currentKey].Content += $trimmed + "`n"
        }
    }

    # 🧱 Build HTML for each section
    $html = ""
    foreach ($key in @("📊", "📋", "🎯", "🧱", "🔧")) {
        $title   = $sections[$key].Title
        $content = $sections[$key].Content.Trim() -replace "\*\*", ""

        if (-not $content) { continue }

        if ($key -eq "🔧") {
            # 🧾 Build 3-column table for recommended actions
            $tableRows = ""
            $actions = $content -split "Risk Addressed:", 0
            foreach ($a in $actions) {
                if ($a.Trim() -eq "") { continue }

                $risk    = ($a -split "Trigger:", 2)[0].Trim()
                $trigger = ($a -split "Trigger:", 2)[1] -split "Action:", 2
                $trigger = $trigger[0].Trim()
                $action  = $a -split "Action:", 2
                $action  = if ($action.Count -eq 2) { $action[1].Trim() } else { "" }

                $tableRows += "<tr><td>$risk</td><td>$trigger</td><td>$action</td></tr>`n"
            }

            $html += @"
            <div class='advisory-section'>
            <table class='advisory-table'>
                <thead><tr><th colspan='3'>$title</th></tr>
                    <tr><th>Risk Addressed</th><th>Trigger</th><th>Action</th></tr></thead>
                <tbody>$tableRows</tbody>
            </table>
            </div>
"@
        }
        else {
            # 📄 Render other sections as single-column tables
            $rows = ""
            foreach ($line in $content -split "`r?`n") {
                $clean = [regex]::Replace($line.Trim(), '\*\*(.+?)\*\*', '<strong>$1</strong>')

                if ($clean) {
                    $rows += "<tr><td>$clean</td></tr>`n"
                }
            }

            $html += @"
                <div class='advisory-section'>
                <table class='advisory-table'>
                    <thead><tr><th>$title</th></tr></thead>
                    <tbody>
                    $rows
                    </tbody>
                </table>
                </div>
"@
        }
    }

    # 🛑 Return fallback if everything failed
    if (-not $html) {
        Write-Log -Type "Alert" -Message "⚠️ Advisory HTML rendering failed – no valid sections found."
        return "<p>No advisory sections detected.</p>"
    }

    return $html
}