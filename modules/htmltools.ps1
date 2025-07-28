function Convert-ToHtmlTable {
    param (
        [Parameter(Mandatory = $true)]
        [array]$Data
    )

    # 🧪 Return placeholder if data is empty
    if (-not $Data -or $Data.Count -eq 0) {
        Write-Host "⚠️ No data available for HTML table." -ForegroundColor DarkYellow
        Write-Log -Type "Alert" -Message "⚠️ Convert-ToHtmlTable: empty dataset – no HTML generated."
        return "<p><i>No data available.</i></p>"
    }

    # 📋 Build table header
    $html = "<table><thead><tr>"
    $firstRow = $Data | Select-Object -First 1
    $columns = $firstRow.PSObject.Properties.Name
    foreach ($col in $columns) {
        $html += "<th>$col</th>"
    }
    $html += "</tr></thead><tbody>"

    # 📊 Add table rows
    foreach ($row in $Data) {
        $html += "<tr>"
        foreach ($col in $columns) {
            $value = $row.$col
            $html += "<td>$value</td>"
        }
        $html += "</tr>"
    }

    $html += "</tbody></table>"

    Write-Log -Type "OK" -Message "✅ HTML table generated with $($Data.Count) rows and $($columns.Count) columns."
    return $html
}

function Convert-AdvisoryToHtml {
    param (
        [string]$Text
    )

    # 🧪 Validate input
    if (-not $Text -or $Text.Trim() -eq '') {
        Write-Log -Type "Alert" -Message "⚠️ Convert-AdvisoryToHtml: input is empty."
        Write-Host "⚠️ Advisory section is empty. Skipping..." -ForegroundColor DarkYellow
        return "<p>No advisory text available.</p>"
    }

    # 🧭 Define advisory blocks
    $sections = @{
        "📊" = @{ Title = "Overall Risk Score";        Content = "" }
        "📋" = @{ Title = "Overall Risk Assessment";   Content = "" }
        "🎯" = @{ Title = "Attack Profile Summary";    Content = "" }
        "🔧" = @{ Title = "Recommended Actions";       Content = "" }
        "🧱" = @{ Title = "Conditional Access Policy Evaluation"; Content = "" }
    }

    # 🔍 Parse lines into sections
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

    # 🧱 Build HTML output
    $html = ""
    foreach ($key in @("📊", "📋", "🎯", "🧱", "🔧")) {
        $title   = $sections[$key].Title
        $content = $sections[$key].Content.Trim() -replace "\*\*", ""

        if (-not $content) { continue }

        if ($key -eq "🔧") {
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

    if (-not $html) {
        Write-Log -Type "Alert" -Message "⚠️ Advisory HTML rendering failed: no sections parsed."
        Write-Host "⚠️ No valid advisory sections found." -ForegroundColor Yellow
        return "<p>No advisory sections detected.</p>"
    }

    Write-Log -Type "OK" -Message "✅ Advisory HTML successfully rendered."
    return $html
}
