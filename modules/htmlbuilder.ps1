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
function Build-IncidentReport {
    param (
        [Parameter(Mandatory)][string[]]$Sections,
        [Parameter(Mandatory)][string]$OutputPath,
        [Parameter(Mandatory)][string]$UserPrincipalName
    )

    Write-Host "🛠️ Building HTML incident report for $UserPrincipalName..." -ForegroundColor Cyan
    Write-Log -Type "Information" -Message "🛠️ Started HTML report generation for: $UserPrincipalName"

    # 🧠 Parse the advisory section into proper HTML format (if needed)
    if ($Sections[0] -match '<div class=''warning''>') {
        $aiSummaryHtml = $Sections[0]
        Write-Log -Type "Information" -Message "⚠️ Using fallback advisory HTML (warning block)."
    } elseif ($Sections[0] -notmatch '<div class=''advisory-section''>') {
        $aiSummaryHtml = Convert-AdvisoryToHtml -Text $Sections[0]
        Write-Log -Type "Information" -Message "🔄 Advisory text converted to HTML via Convert-AdvisoryToHtml."
    } else {
        $aiSummaryHtml = $Sections[0]
        Write-Log -Type "Information" -Message "✅ Advisory HTML already in correct format."
    }

    # ⚠️ Extract the user and sign-in risk sections
    $userRiskHtml = $Sections[1]
    $signInHtml   = $Sections[2]

    # 🪵 Log the length of each section for diagnostics
    Write-Log -Type "Debug" -Message "📏 Advisory section length: $($Sections[0].Length)"
    Write-Log -Type "Debug" -Message "📏 UserRisk section length:  $($Sections[1].Length)"
    Write-Log -Type "Debug" -Message "📏 SignIn section length:   $($Sections[2].Length)"

    # 🧱 Construct final HTML content
    $html = @"
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Risky User Troubleshooter – $UserPrincipalName</title>
  <link rel="icon" type="image/x-icon" href="../modules/virtualite.ico">
  <style>
    :root {
      --primary-blue: #0a72d0;
      --accent-green: #2cc29f;
      --neutral: #f3f2f1;
      --bg-dark: #1b1b1f;
      --card-dark: #25252a;
      --text-light: #ffffff;
      --text-muted: #cccccc;
    }

    body {
      margin: 0;
      font-family: "Segoe UI", sans-serif;
      background: var(--bg-dark);
      color: var(--text-light);
    }

    header {
      background: var(--card-dark);
      display: flex;
      justify-content: space-between;
      align-items: center;
      padding: 1rem 2rem;
      border-bottom: 1px solid #333;
    }

    header img {
      height: 45px;
      margin-left: 1rem;
    }

    header h1 {
      font-size: 1.8rem;
      color: var(--primary-blue);
      margin: 0;
      flex-grow: 1;
    }

    .title-primary {
      color: var(--primary-blue);
      margin-right: 0.5rem;
    }

    .title-tenant {
      color: var(--accent-green);
    }

    nav {
      display: flex;
      background: linear-gradient(90deg, #0a72d0 0%, #3c9cdc 100%);
      border: 1px solid #1e1e1e;
      border-radius: 10px;
      margin: 2rem;
      overflow: hidden;
      box-shadow: 0 2px 8px rgba(0, 0, 0, 0.25);
    }

    nav button {
      flex: 1;
      padding: 1rem;
      background: transparent;
      border: none;
      font-size: 1rem;
      color: #eeeeee;
      font-weight: 520;
      cursor: pointer;
      transition: background 0.3s ease, transform 0.2s ease;
    }

    nav button:hover {
      background-color: rgba(255, 255, 255, 0.08);
      transform: scale(1.015);
      color: #ffffff;
    }

    nav button.active {
      font-weight: 600;
      color: #ffffff;
      background-color: rgba(255, 255, 255, 0.12);
    }

    .tab-content {
      display: none;
      padding: 2rem;
      background: var(--card-dark);
      margin: 2rem;
      border-radius: 10px;
      box-shadow: 0 0 10px rgba(0,0,0,0.4);
    }

    .tab-content.active {
      display: block;
    }

  .popup {
    display: none;
    position: fixed;
    top: 50%;
    left: 50%;
    transform: translate(-50%, -50%);
    background-color: #25252a;
    color: #fff;
    border: 1px solid #444;
    border-radius: 10px;
    z-index: 1001;
    width: 800px;          
    max-width: 95vw;      
    box-shadow: 0 0 20px rgba(0,0,0,0.6);
    overflow: hidden;       
  }

  .popup-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    padding: 1rem 2rem 0.5rem 2rem;
    background: #25252a;
    border-bottom: 1px solid #444;
    position: sticky;
    top: 0;
    z-index: 2;
    width: 100%;
    box-sizing: border-box;
  }

  .popup-header h3 {
    margin: 0;
    font-size: 1.25rem;
    color: #ffffff;
  }

  .popup-close {
    font-size: 1.5rem;
    color: #ffffff;
    cursor: pointer;
    transition: color 0.2s ease-in-out, transform 0.1s ease;
  }

  .popup-close:hover {
    color: var(--accent-green);
    transform: scale(1.2);
  }

  .popup-body {
    max-height: 70vh;
    overflow-y: auto;
    padding: 1rem 2rem 2rem 2rem;
    width: 100%;
    box-sizing: border-box;
  }

  .popup-body::-webkit-scrollbar {
    width: 10px;
  }

  .popup-body::-webkit-scrollbar-track {
    background: #2a2a2f;
  }

  .popup-body::-webkit-scrollbar-thumb {
    background-color: #555;
    border-radius: 6px;
    border: 2px solid #2a2a2f;
  }

  .popup-body::-webkit-scrollbar-thumb:hover {
    background-color: #777;
  }

    table {
      width: 100%;
      border-collapse: collapse;
      background: #1f1f23;
      color: var(--text-light);
    }

    th, td {
      padding: 0.75rem;
      text-align: left;
      border-bottom: 1px solid #333;
      vertical-align: top;
    }

    th {
      background-color: #2c2c31;
      color: var(--accent-green);
    }

    tbody tr:hover {
      background-color: rgba(10, 114, 208, 0.12);
    }

    .advisory-section {
      background: var(--card-dark);
      border: none;
      border-radius: 8px;
      margin-bottom: 8px;
      padding: 8px 12px;
    }

    .advisory-section h3 {
      font-size: 1.1em;
      margin-top: 0;
      color: var(--accent-green);
      display: flex;
      align-items: center;
      gap: 0.5em;
    }

    .advisory-section p {
      margin: 0.3em 0 0 0;
      color: var(--text-light);
      line-height: 1.4;
    }

    .advisory-section strong {
      color: #fff;
    }

    .advisory-table {
      width: 100%;
      margin-top: 10px;
      border-collapse: collapse;
    }

    .advisory-table th, .advisory-table td {
      padding: 8px;
      border: 1px solid #333;
      color: var(--text-light);
    }

    .advisory-table th {
      background-color: #2c2c31;
      color: var(--accent-green);
      text-align: left;
    }
        .warning {
    background-color: #fff3cd;
    color: #856404;
    padding: 10px;
    border-left: 6px solid #ffeeba;
    margin-bottom: 15px;
    border-radius: 6px;
    font-size: 0.95em;
  }
  </style>
  <script>
  // ✅ Show the selected tab and activate its button
  function showTab(tabId) {
    document.querySelectorAll('.tab-content').forEach(tab => tab.classList.remove('active'));
    document.querySelectorAll('nav button').forEach(btn => btn.classList.remove('active'));

    document.getElementById(tabId).classList.add('active');

    document.querySelectorAll('nav button').forEach(btn => {
      if (btn.getAttribute("onclick").includes(tabId)) {
        btn.classList.add("active");
      }
    });
  }

  // ✅ Open a popup and ensure only one is open
  function openPopup(id) {
    closeAllPopups(); // Close any currently open popups
    const popup = document.getElementById(id);
    popup.style.display = 'block';

    // Add temporary click listener to close popup when clicking outside
    setTimeout(() => {
      const handler = function (e) {
        if (!popup.contains(e.target)) {
          popup.style.display = 'none';
          document.removeEventListener('click', handler); // Remove listener after execution
        }
      };
      document.addEventListener('click', handler);
    }, 0);
  }

  // ✅ Close a specific popup
  function closePopup(id) {
    document.getElementById(id).style.display = 'none';
  }

  // ✅ Close all open popups
  function closeAllPopups() {
    document.querySelectorAll('.popup').forEach(p => p.style.display = 'none');
  }

  // ✅ Close all popups when Escape key is pressed
  document.addEventListener('keydown', function(e) {
    if (e.key === "Escape") {
      closeAllPopups();
    }
  });
</script>

</head>
  <body>
    <header>
      <h1>
        <span class="title-primary">Risky User Troubleshooter</span>
        <span class="title-tenant">$UserPrincipalName</span>
      </h1>
      <img src="../modules/virtualite.png" alt="Virtualite Logo">
    </header>

    <nav>
      <button onclick="showTab('summary')" class="active">🧠 OpenAI Advisory</button>
      <button onclick="showTab('userrisk')">⚠️ User Risk</button>
      <button onclick="showTab('signins')">📄 Sign-ins</button>
    </nav>

    <div id="summary" class="tab-content active">
      $aiSummaryHtml
    </div>

    <div id="userrisk" class="tab-content">
      $userRiskHtml
    </div>

    <div id="signins" class="tab-content">
"@

    # 🕵️ Log AbuseIPDB API key warning flag
    $abuseFlag = $global:ABUSEIPDB_APIKEY_WARNING -as [bool]
    Write-Log -Type "Information" -Message "⚠️ AbuseIPDB API Key Warning Flag: $abuseFlag"

    if ($abuseFlag) {
        $html += @"
      <div class='warning'>
        <h4>⚠️ AbuseIPDB Reputation Check Skipped</h4>
        <p>
          The AbuseIPDB API key was not configured.<br>
          All IP reputation scores were set to <code>0</code>, which may underestimate the actual risk.
        </p>
      </div>
"@
    }

    # 📄 Append sign-in section
    $html += $signInHtml

    # 🧾 Final HTML close
    $html += @"
    </div>
  </body>
</html>
"@

    # 💾 Save the HTML report
    try {
        $html | Out-File -FilePath $OutputPath -Encoding UTF8
        Write-Log -Type "OK" -Message "✅ HTML report successfully written to: $OutputPath"
        Write-Host "✅ HTML report created: $OutputPath" -ForegroundColor Green
    } catch {
        Write-Log -Type "Error" -Message "❌ Failed to write HTML report: $($_.Exception.Message)"
        Write-Host "❌ Failed to write HTML report. Check permissions or path." -ForegroundColor Red
    }
}