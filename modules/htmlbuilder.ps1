<#
.SYNOPSIS
    Microsoft 365 Risky User Troubleshooter - HTML Report Builder

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
function Build-IncidentReport {
    param (
        [Parameter(Mandatory)][string[]]$Sections,
        [Parameter(Mandatory)][string]$OutputPath,
        [Parameter(Mandatory)][string]$UserPrincipalName
    )

    Write-Host "Building HTML incident report for $UserPrincipalName..." -ForegroundColor Cyan
    Write-Log -Type "Information" -Message "Started HTML report generation for: $UserPrincipalName"

    # Parse the advisory section into proper HTML format (if needed)
    if ($Sections[0] -match '<div class=''warning''>') {
        $summaryHtml = $Sections[0]
        Write-Log -Type "Information" -Message "Using fallback advisory HTML (warning block)."
    } elseif ($Sections[0] -notmatch '<div class=''advisory-section''>') {
        $summaryHtml = Convert-AdvisoryToHtml -Text $Sections[0]
        Write-Log -Type "Information" -Message "Advisory text converted to HTML via Convert-AdvisoryToHtml."
    } else {
        $summaryHtml = $Sections[0]
        Write-Log -Type "Information" -Message "Advisory HTML already in correct format."
    }

    # Extract the user and sign-in risk sections
    $userRiskHtml = $Sections[1]
    $signInHtml   = $Sections[2]

    # Log the length of each section for diagnostics
    Write-Log -Type "Debug" -Message "Advisory section length: $($Sections[0].Length)"
    Write-Log -Type "Debug" -Message "UserRisk section length:  $($Sections[1].Length)"
    Write-Log -Type "Debug" -Message "SignIn section length:   $($Sections[2].Length)"

    # Generate timestamp for report
    $reportTimestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"

    # Construct final HTML content with accessibility improvements
    $html = @"
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="description" content="Security risk analysis report for $UserPrincipalName">
  <meta name="generator" content="RiskyUserTroubleshooter by Virtualite.nl">
  <title>Risky User Troubleshooter - $UserPrincipalName</title>
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
      --status-good: #2cc29f;
      --status-warning: #f0ad4e;
      --status-bad: #dc3545;
      --status-critical: #8b0000;
    }

    /* Reset and base styles */
    *, *::before, *::after {
      box-sizing: border-box;
    }

    body {
      margin: 0;
      font-family: "Segoe UI", -apple-system, BlinkMacSystemFont, sans-serif;
      background: var(--bg-dark);
      color: var(--text-light);
      line-height: 1.5;
    }

    /* Navigation / Tab bar with ARIA */
    nav[role="tablist"] {
      display: flex;
      background: var(--card-dark);
      border: 1px solid #333;
      border-radius: 8px;
      margin: 0 2rem 2rem 2rem;
      overflow: hidden;
      gap: 2px;
    }

    nav[role="tablist"] button[role="tab"] {
      flex: 1;
      min-width: 120px;
      padding: 0.875rem 1rem;
      background: transparent;
      border: none;
      font-size: 0.95rem;
      color: var(--text-muted);
      font-weight: 500;
      cursor: pointer;
      transition: background 0.2s ease, color 0.2s ease;
      border-bottom: 2px solid transparent;
    }

    nav[role="tablist"] button[role="tab"]:hover {
      background-color: rgba(255, 255, 255, 0.05);
      color: var(--text-light);
    }

    nav[role="tablist"] button[role="tab"]:focus {
      outline: 2px solid var(--accent-green);
      outline-offset: -2px;
    }

    nav[role="tablist"] button[role="tab"][aria-selected="true"] {
      font-weight: 600;
      color: var(--accent-green);
      background-color: rgba(44, 194, 159, 0.1);
      border-bottom: 2px solid var(--accent-green);
    }

    /* Tab content panels */
    .tab-content[role="tabpanel"] {
      display: none;
      padding: 2rem;
      background: var(--card-dark);
      margin: 2rem;
      border-radius: 10px;
      box-shadow: 0 0 10px rgba(0,0,0,0.4);
    }

    .tab-content[role="tabpanel"].active {
      display: block;
    }

    @media (max-width: 768px) {
      .tab-content[role="tabpanel"] {
        padding: 1rem;
        margin: 1rem;
      }
      nav[role="tablist"] {
        margin: 1rem;
      }
    }

    /* Popup / Modal with ARIA */
    .popup[role="dialog"] {
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
      height: auto;
      max-height: 80vh;
      box-shadow: 0 0 20px rgba(0,0,0,0.6);
      overflow: hidden;
    }

    .popup[role="dialog"].visible {
      display: block !important;
    }

    .popup-overlay {
      display: none;
      position: fixed;
      top: 0;
      left: 0;
      width: 100%;
      height: 100%;
      background: rgba(0, 0, 0, 0.15);
      z-index: 1000;
    }

    .popup-overlay.active {
      display: block;
      pointer-events: none;
    }

    .popup-header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      padding: 1rem 2rem 0.5rem 2rem;
      background: #25252a;
      border-bottom: 1px solid #444;
      flex-shrink: 0;
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
      background: none;
      border: none;
      padding: 0.5rem;
      line-height: 1;
    }

    .popup-close:hover,
    .popup-close:focus {
      color: var(--accent-green);
      transform: scale(1.2);
      outline: 2px solid var(--accent-green);
    }

    .popup[role="dialog"] > .popup-body,
    div.popup-body {
      display: block !important;
      overflow: auto !important;
      overflow-y: auto !important;
      overflow-x: auto !important;
      padding: 1rem 2rem 2rem 2rem;
      width: 100%;
      box-sizing: border-box;
      height: calc(80vh - 70px) !important;
      max-height: calc(80vh - 70px) !important;
      overscroll-behavior: contain;
    }

    /* Prevent background scrolling when popup is open */
    body.popup-open {
      overflow: hidden;
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

    /* Tables */
    .table-container {
      overflow-x: auto;
      margin-bottom: 1rem;
    }

    table {
      width: 100%;
      border-collapse: collapse;
      background: #1f1f23;
      color: var(--text-light);
      min-width: 400px;
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
      position: sticky;
      top: 0;
    }

    /* Disable sticky headers inside popups to prevent scroll issues */
    .popup-body th {
      position: static;
    }

    tbody tr:hover {
      background-color: rgba(10, 114, 208, 0.12);
    }

    tbody tr:focus-within {
      outline: 2px solid var(--primary-blue);
      outline-offset: -2px;
    }

    /* Status indicators (color + weight, no ::before prefixes to avoid duplication) */
    .status-good {
      color: var(--status-good);
      font-weight: bold;
    }

    .status-warning {
      color: var(--status-warning);
      font-weight: bold;
    }

    .status-bad {
      color: var(--status-bad);
      font-weight: bold;
    }

    .status-critical {
      color: var(--status-critical);
      font-weight: bold;
    }

    /* Risk score badge */
    .risk-badge {
      display: inline-flex;
      align-items: center;
      gap: 0.5rem;
      padding: 0.5rem 1rem;
      border-radius: 6px;
      font-weight: bold;
      font-size: 1.2rem;
    }

    .risk-badge.low {
      background: rgba(44, 194, 159, 0.2);
      border: 2px solid var(--status-good);
      color: var(--status-good);
    }

    .risk-badge.medium {
      background: rgba(240, 173, 78, 0.2);
      border: 2px solid var(--status-warning);
      color: var(--status-warning);
    }

    .risk-badge.high {
      background: rgba(220, 53, 69, 0.2);
      border: 2px solid var(--status-bad);
      color: var(--status-bad);
    }

    .risk-badge.critical {
      background: rgba(139, 0, 0, 0.2);
      border: 2px solid var(--status-critical);
      color: var(--status-critical);
    }

    /* Advisory sections */
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

    /* Warning box */
    .warning {
      background-color: #fff3cd;
      color: #856404;
      padding: 10px;
      border-left: 6px solid #ffeeba;
      margin-bottom: 15px;
      border-radius: 6px;
      font-size: 0.95em;
    }

    .warning h4 {
      margin: 0 0 0.5rem 0;
    }

    /* Collapsible sections */
    .collapsible {
      background-color: #2c2c31;
      color: var(--text-light);
      cursor: pointer;
      padding: 1rem;
      width: 100%;
      border: none;
      text-align: left;
      outline: none;
      font-size: 1rem;
      border-radius: 6px;
      margin-bottom: 0.5rem;
      display: flex;
      justify-content: space-between;
      align-items: center;
    }

    .collapsible:hover {
      background-color: #3c3c41;
    }

    .collapsible:focus {
      outline: 2px solid var(--primary-blue);
    }

    .collapsible::after {
      content: '+';
      font-weight: bold;
      margin-left: 1rem;
    }

    .collapsible.active::after {
      content: '-';
    }

    .collapsible-content {
      max-height: 0;
      overflow: hidden;
      transition: max-height 0.3s ease-out;
      background-color: var(--card-dark);
      border-radius: 0 0 6px 6px;
    }

    .collapsible-content.show {
      max-height: 2000px;
      padding: 1rem;
    }

    /* Copy button */
    .copy-btn {
      background: var(--primary-blue);
      color: white;
      border: none;
      padding: 0.25rem 0.5rem;
      border-radius: 4px;
      cursor: pointer;
      font-size: 0.8rem;
      margin-left: 0.5rem;
    }

    .copy-btn:hover {
      background: #0861b0;
    }

    .copy-btn:focus {
      outline: 2px solid var(--accent-green);
    }

    .copy-btn.copied {
      background: var(--status-good);
    }

    /* Footer */
    footer {
      text-align: center;
      padding: 1rem;
      color: var(--text-muted);
      font-size: 0.85rem;
      border-top: 1px solid #333;
      margin-top: 2rem;
    }

    footer a {
      color: var(--accent-green);
      text-decoration: none;
    }

    footer a:hover {
      text-decoration: underline;
    }

    /* ========================================
       UI/UX ENHANCEMENTS
       ======================================== */

    /* Executive Summary Card */
    .executive-summary {
      background: linear-gradient(135deg, var(--card-dark) 0%, #2a2a35 100%);
      border-radius: 12px;
      padding: 1.5rem 2rem;
      margin: 1.5rem 2rem 1rem 2rem;
      display: grid;
      grid-template-columns: auto 1fr auto;
      gap: 2rem;
      align-items: center;
      box-shadow: 0 4px 20px rgba(0, 0, 0, 0.3);
      border: 1px solid #333;
    }

    @media (max-width: 900px) {
      .executive-summary {
        grid-template-columns: 1fr;
        text-align: center;
      }
    }

    .risk-gauge {
      position: relative;
      width: 140px;
      height: 140px;
    }

    .risk-gauge svg {
      transform: rotate(-90deg);
      width: 140px;
      height: 140px;
    }

    .risk-gauge-bg {
      fill: none;
      stroke: #333;
      stroke-width: 12;
    }

    .risk-gauge-fill {
      fill: none;
      stroke-width: 12;
      stroke-linecap: round;
      transition: all 1s ease-out;
    }

    .risk-gauge-text {
      position: absolute;
      top: 50%;
      left: 50%;
      transform: translate(-50%, -50%);
      text-align: center;
    }

    .risk-gauge-score {
      font-size: 2rem;
      font-weight: bold;
      line-height: 1;
    }

    .risk-gauge-label {
      font-size: 0.75rem;
      color: var(--text-muted);
      text-transform: uppercase;
      letter-spacing: 1px;
    }

    .summary-details {
      display: flex;
      flex-direction: column;
      gap: 0.5rem;
    }

    .summary-details h2 {
      margin: 0;
      font-size: 1.5rem;
      color: var(--text-light);
    }

    .summary-details .risk-level {
      font-size: 1.1rem;
      font-weight: 600;
    }

    .summary-details .timestamp {
      font-size: 0.85rem;
      color: var(--text-muted);
    }

    /* Quick Stats Bar */
    .quick-stats {
      display: flex;
      gap: 1rem;
      flex-wrap: wrap;
      justify-content: flex-end;
    }

    .stat-card {
      background: rgba(0, 0, 0, 0.3);
      border-radius: 8px;
      padding: 0.75rem 1.25rem;
      text-align: center;
      width: 120px;
      flex: 0 0 120px;
      border: 1px solid #444;
      transition: transform 0.2s ease, border-color 0.2s ease;
    }

    .stat-card:hover {
      transform: translateY(-2px);
      border-color: var(--primary-blue);
    }

    .stat-card .stat-value {
      font-size: 1.5rem;
      font-weight: bold;
      line-height: 1.2;
      color: var(--text-light);
    }

    .stat-card .stat-label {
      font-size: 0.7rem;
      color: var(--text-muted);
      text-transform: uppercase;
      letter-spacing: 0.5px;
    }

    /* Tab Badges */
    .tab-badge {
      display: inline-flex;
      align-items: center;
      justify-content: center;
      min-width: 20px;
      height: 20px;
      padding: 0 6px;
      border-radius: 10px;
      font-size: 0.75rem;
      font-weight: 600;
      margin-left: 8px;
      background: rgba(44, 194, 159, 0.2);
      color: var(--accent-green);
      border: 1px solid rgba(44, 194, 159, 0.3);
    }

    nav[role="tablist"] button[role="tab"][aria-selected="true"] .tab-badge {
      background: rgba(44, 194, 159, 0.3);
      color: var(--accent-green);
      border-color: rgba(44, 194, 159, 0.5);
    }

    /* Sortable Tables */
    th.sortable {
      cursor: pointer;
      user-select: none;
      position: relative;
      padding-right: 1.5rem;
    }

    th.sortable:hover {
      background-color: #3a3a40;
    }

    th.sortable::after {
      content: '⇅';
      position: absolute;
      right: 0.5rem;
      opacity: 0.4;
      font-size: 0.8rem;
    }

    th.sortable.asc::after {
      content: '↑';
      opacity: 1;
    }

    th.sortable.desc::after {
      content: '↓';
      opacity: 1;
    }

    /* Copy Button Enhancements */
    .copy-inline {
      display: inline-flex;
      align-items: center;
      gap: 0.25rem;
    }

    .copy-icon {
      cursor: pointer;
      opacity: 0.5;
      transition: opacity 0.2s ease, transform 0.1s ease;
      font-size: 0.9rem;
      padding: 2px 4px;
      border-radius: 3px;
    }

    .copy-icon:hover {
      opacity: 1;
      background: rgba(255, 255, 255, 0.1);
    }

    .copy-icon.copied {
      color: var(--status-good);
      opacity: 1;
    }

    /* Timeline Visualization */
    .timeline {
      position: relative;
      padding: 1rem 0;
      margin: 1rem 0;
    }

    .timeline::before {
      content: '';
      position: absolute;
      left: 20px;
      top: 0;
      bottom: 0;
      width: 2px;
      background: linear-gradient(to bottom, var(--primary-blue), var(--accent-green));
    }

    .timeline-item {
      position: relative;
      padding-left: 50px;
      padding-bottom: 1.5rem;
      opacity: 0;
      animation: fadeInSlide 0.4s ease forwards;
    }

    .timeline-item:nth-child(1) { animation-delay: 0.1s; }
    .timeline-item:nth-child(2) { animation-delay: 0.2s; }
    .timeline-item:nth-child(3) { animation-delay: 0.3s; }
    .timeline-item:nth-child(4) { animation-delay: 0.4s; }
    .timeline-item:nth-child(5) { animation-delay: 0.5s; }

    .timeline-marker {
      position: absolute;
      left: 12px;
      width: 18px;
      height: 18px;
      border-radius: 50%;
      background: var(--card-dark);
      border: 3px solid var(--primary-blue);
      z-index: 1;
    }

    .timeline-marker.risk-low { border-color: var(--status-good); }
    .timeline-marker.risk-medium { border-color: var(--status-warning); }
    .timeline-marker.risk-high { border-color: var(--status-bad); }
    .timeline-marker.risk-critical { border-color: var(--status-critical); }

    .timeline-content {
      background: rgba(0, 0, 0, 0.2);
      border-radius: 8px;
      padding: 0.75rem 1rem;
      border: 1px solid #333;
      transition: border-color 0.2s ease, transform 0.2s ease;
    }

    .timeline-content:hover {
      border-color: var(--primary-blue);
      transform: translateX(4px);
    }

    .timeline-time {
      font-size: 0.8rem;
      color: var(--text-muted);
      margin-bottom: 0.25rem;
    }

    .timeline-title {
      font-weight: 600;
      margin-bottom: 0.25rem;
    }

    .timeline-details {
      font-size: 0.85rem;
      color: var(--text-muted);
    }

    /* Enhanced Animations */
    @keyframes fadeInSlide {
      from {
        opacity: 0;
        transform: translateX(-10px);
      }
      to {
        opacity: 1;
        transform: translateX(0);
      }
    }

    @keyframes fadeIn {
      from { opacity: 0; }
      to { opacity: 1; }
    }

    @keyframes pulse {
      0%, 100% { transform: scale(1); }
      50% { transform: scale(1.05); }
    }

    @keyframes slideDown {
      from {
        opacity: 0;
        transform: translateY(-10px);
      }
      to {
        opacity: 1;
        transform: translateY(0);
      }
    }

    .fade-in {
      animation: fadeIn 0.3s ease forwards;
    }

    .slide-down {
      animation: slideDown 0.3s ease forwards;
    }

    /* Row click animation */
    tbody tr {
      transition: background-color 0.15s ease, transform 0.1s ease;
    }

    tbody tr:active {
      transform: scale(0.995);
    }

    tbody tr.clickable {
      cursor: pointer;
    }

    tbody tr.clickable:hover {
      background-color: rgba(10, 114, 208, 0.18);
    }

    /* Tooltip */
    .tooltip {
      position: relative;
    }

    .tooltip::after {
      content: attr(data-tooltip);
      position: absolute;
      bottom: 100%;
      left: 50%;
      transform: translateX(-50%);
      padding: 0.5rem 0.75rem;
      background: #000;
      color: white;
      font-size: 0.8rem;
      border-radius: 4px;
      white-space: nowrap;
      opacity: 0;
      pointer-events: none;
      transition: opacity 0.2s ease;
      z-index: 100;
    }

    .tooltip:hover::after {
      opacity: 1;
    }

    /* Filter/Search box */
    .table-filter {
      display: flex;
      gap: 1rem;
      margin-bottom: 1rem;
      flex-wrap: wrap;
    }

    .filter-input {
      flex: 1;
      min-width: 200px;
      padding: 0.5rem 1rem;
      border: 1px solid #444;
      border-radius: 6px;
      background: #1f1f23;
      color: var(--text-light);
      font-size: 0.9rem;
    }

    .filter-input:focus {
      outline: none;
      border-color: var(--primary-blue);
      box-shadow: 0 0 0 2px rgba(10, 114, 208, 0.2);
    }

    .filter-input::placeholder {
      color: #666;
    }

    /* Smooth scroll */
    html {
      scroll-behavior: smooth;
    }

    /* Focus visible for better keyboard navigation */
    :focus-visible {
      outline: 2px solid var(--accent-green);
      outline-offset: 2px;
    }

    /* Improved popup animation */
    .popup.visible {
      animation: popupAppear 0.25s ease forwards;
    }

    @keyframes popupAppear {
      from {
        opacity: 0;
        transform: translate(-50%, -50%) scale(0.95);
      }
      to {
        opacity: 1;
        transform: translate(-50%, -50%) scale(1);
      }
    }

    /* Print styles */
    @media print {
      body {
        background: white;
        color: black;
      }

      header, footer {
        background: white;
        border: none;
      }

      .title-primary, .title-tenant {
        color: black;
      }

      nav[role="tablist"] {
        display: none;
      }

      .tab-content[role="tabpanel"] {
        display: block !important;
        background: white;
        box-shadow: none;
        margin: 0;
        padding: 1rem 0;
        page-break-inside: avoid;
      }

      .tab-content[role="tabpanel"]::before {
        content: attr(aria-label);
        display: block;
        font-size: 1.5rem;
        font-weight: bold;
        margin-bottom: 1rem;
        border-bottom: 2px solid #333;
        padding-bottom: 0.5rem;
      }

      .popup, .popup-overlay {
        display: none !important;
      }

      table {
        background: white;
        color: black;
      }

      th {
        background: #f0f0f0;
        color: black;
      }

      .status-good { color: green; }
      .status-warning { color: orange; }
      .status-bad { color: red; }
      .status-critical { color: darkred; }

      .warning {
        border: 2px solid #856404;
      }

      .copy-btn, .collapsible::after {
        display: none;
      }

      .collapsible-content {
        max-height: none !important;
        padding: 1rem !important;
      }

      a {
        text-decoration: underline;
      }

      a[href]::after {
        content: " (" attr(href) ")";
        font-size: 0.8em;
      }

      .fp-toggle {
        display: none !important;
      }
    }

    /* ========================================
       FALSE POSITIVE MARKING STYLES
       ======================================== */

    /* Row marked as false positive */
    .false-positive {
      opacity: 0.5;
      text-decoration: line-through;
      background-color: rgba(108, 117, 125, 0.1) !important;
    }

    .false-positive td {
      text-decoration: line-through;
    }

    .false-positive .fp-toggle {
      text-decoration: none;
    }

    /* False positive toggle button */
    .fp-toggle {
      padding: 4px 10px;
      border-radius: 4px;
      cursor: pointer;
      font-size: 0.75rem;
      font-weight: 500;
      border: 1px solid #555;
      background: transparent;
      color: var(--text-muted);
      transition: all 0.2s ease;
      white-space: nowrap;
    }

    .fp-toggle:hover {
      background: rgba(255, 255, 255, 0.1);
      border-color: var(--primary-blue);
      color: var(--text-light);
    }

    .fp-toggle:focus {
      outline: 2px solid var(--accent-green);
      outline-offset: 1px;
    }

    /* Button state when item is marked as FP */
    .false-positive .fp-toggle {
      background: rgba(44, 194, 159, 0.2);
      border-color: var(--status-good);
      color: var(--status-good);
      opacity: 1;
    }

    .false-positive .fp-toggle:hover {
      background: rgba(44, 194, 159, 0.3);
    }

    /* FP column header */
    th.fp-column {
      width: 80px;
      text-align: center;
    }

    td.fp-cell {
      text-align: center;
      text-decoration: none !important;
    }

    /* ========================================
       RISK SUMMARY CLICKABLE ROWS
       ======================================== */

    /* Clickable breach signal and config risk rows */
    .clickable-risk,
    [data-breach-id],
    [data-config-id]:not([data-no-fp]) {
      cursor: pointer;
      transition: background-color 0.2s ease, transform 0.1s ease;
    }

    .clickable-risk:hover,
    [data-breach-id]:hover,
    [data-config-id]:not([data-no-fp]):hover {
      background-color: rgba(10, 114, 208, 0.15) !important;
    }

    .clickable-risk:active,
    [data-breach-id]:active,
    [data-config-id]:not([data-no-fp]):active {
      transform: scale(0.995);
    }

    /* Non-FP items (objective facts) - not clickable */
    [data-no-fp] {
      cursor: default;
    }

    [data-no-fp]:hover {
      background-color: transparent !important;
    }

    /* Highlight animation for scroll-to effect */
    .highlight {
      animation: highlightPulse 2s ease;
    }

    @keyframes highlightPulse {
      0%, 100% { background-color: transparent; }
      25%, 75% { background-color: rgba(44, 194, 159, 0.3); }
    }

    /* Dynamic popup (reuse existing popup styles) */
    #dynamic-popup {
      display: none;
    }

    #dynamic-popup.visible {
      display: block !important;
    }

    #dynamic-popup .popup-body table {
      margin-top: 0.5rem;
    }

    #dynamic-popup .popup-body table td {
      padding: 0.5rem 0.75rem;
    }

    #dynamic-popup .popup-body a {
      color: var(--accent-green);
      text-decoration: none;
    }

    #dynamic-popup .popup-body a:hover {
      text-decoration: underline;
    }
  </style>
  <script>
  // Show the selected tab and update ARIA states
  function showTab(tabId) {
    // Track tab switch time to prevent auto-popup
    lastTabSwitch = Date.now();

    // Update tab panels
    document.querySelectorAll('.tab-content').forEach(tab => {
      tab.classList.remove('active');
      tab.setAttribute('aria-hidden', 'true');
    });

    // Update tab buttons
    document.querySelectorAll('nav[role="tablist"] button[role="tab"]').forEach(btn => {
      btn.setAttribute('aria-selected', 'false');
      btn.setAttribute('tabindex', '-1');
    });

    // Activate selected panel
    const panel = document.getElementById(tabId);
    panel.classList.add('active');
    panel.setAttribute('aria-hidden', 'false');

    // Activate selected tab button
    const activeTab = document.querySelector('button[aria-controls="' + tabId + '"]');
    activeTab.setAttribute('aria-selected', 'true');
    activeTab.setAttribute('tabindex', '0');
  }

  // Keyboard navigation for tabs
  function handleTabKeydown(e) {
    const tabs = Array.from(document.querySelectorAll('nav[role="tablist"] button[role="tab"]'));
    const currentIndex = tabs.indexOf(e.target);

    let newIndex;
    switch(e.key) {
      case 'ArrowLeft':
        newIndex = currentIndex === 0 ? tabs.length - 1 : currentIndex - 1;
        break;
      case 'ArrowRight':
        newIndex = currentIndex === tabs.length - 1 ? 0 : currentIndex + 1;
        break;
      case 'Home':
        newIndex = 0;
        break;
      case 'End':
        newIndex = tabs.length - 1;
        break;
      default:
        return;
    }

    e.preventDefault();
    tabs[newIndex].focus();
    tabs[newIndex].click();
  }

  // Open popup with proper ARIA and focus management
  function openPopup(id) {
    closeAllPopups();

    const popup = document.getElementById(id);
    const overlay = document.getElementById('popup-overlay');

    popup.classList.add('visible');
    overlay.classList.add('active');
    popup.setAttribute('aria-hidden', 'false');
    document.body.classList.add('popup-open');

    // Store the element that opened the popup
    popup.dataset.opener = document.activeElement?.id || '';

    // Focus the close button
    const closeBtn = popup.querySelector('.popup-close');
    if (closeBtn) closeBtn.focus();

    // Trap focus within popup
    popup.addEventListener('keydown', trapFocus);
  }

  // Close a specific popup
  function closePopup(id) {
    const popup = document.getElementById(id);
    const overlay = document.getElementById('popup-overlay');

    popup.classList.remove('visible');
    overlay.classList.remove('active');
    popup.setAttribute('aria-hidden', 'true');
    document.body.classList.remove('popup-open');

    popup.removeEventListener('keydown', trapFocus);

    // Return focus to opener
    const openerId = popup.dataset.opener;
    if (openerId) {
      const opener = document.getElementById(openerId);
      if (opener) opener.focus();
    }
  }

  // Close all open popups
  function closeAllPopups() {
    document.querySelectorAll('.popup').forEach(p => {
      p.classList.remove('visible');
      p.setAttribute('aria-hidden', 'true');
      p.removeEventListener('keydown', trapFocus);
    });
    document.getElementById('popup-overlay')?.classList.remove('active');
    document.body.classList.remove('popup-open');
  }

  // Trap focus within popup
  function trapFocus(e) {
    if (e.key !== 'Tab') return;

    const popup = e.currentTarget;
    const focusable = popup.querySelectorAll('button, [href], input, select, textarea, [tabindex]:not([tabindex="-1"])');
    const first = focusable[0];
    const last = focusable[focusable.length - 1];

    if (e.shiftKey && document.activeElement === first) {
      e.preventDefault();
      last.focus();
    } else if (!e.shiftKey && document.activeElement === last) {
      e.preventDefault();
      first.focus();
    }
  }

  // Copy text to clipboard
  function copyToClipboard(text, btn) {
    navigator.clipboard.writeText(text).then(() => {
      const originalText = btn.textContent;
      btn.textContent = 'Copied!';
      btn.classList.add('copied');
      setTimeout(() => {
        btn.textContent = originalText;
        btn.classList.remove('copied');
      }, 2000);
    });
  }

  // Toggle collapsible sections
  function toggleCollapsible(element) {
    element.classList.toggle('active');
    const content = element.nextElementSibling;
    content.classList.toggle('show');
    element.setAttribute('aria-expanded', content.classList.contains('show'));
  }

  // ========================================
  // UI/UX ENHANCEMENTS
  // ========================================

  // Track tab switches to prevent auto-popup on tab change
  let lastTabSwitch = 0;

  // Copy to clipboard with inline feedback
  function copyValue(text, iconElement) {
    navigator.clipboard.writeText(text).then(() => {
      const originalText = iconElement.textContent;
      iconElement.textContent = '✓';
      iconElement.classList.add('copied');
      setTimeout(() => {
        iconElement.textContent = originalText;
        iconElement.classList.remove('copied');
      }, 1500);
    }).catch(err => {
      console.error('Copy failed:', err);
    });
  }

  // Sortable tables
  function sortTable(table, columnIndex, type = 'string') {
    const tbody = table.querySelector('tbody');
    const rows = Array.from(tbody.querySelectorAll('tr:not(.cluster-details)'));
    const header = table.querySelectorAll('th')[columnIndex];

    // Determine sort direction
    const isAsc = header.classList.contains('asc');

    // Remove sort classes from all headers
    table.querySelectorAll('th').forEach(th => {
      th.classList.remove('asc', 'desc');
    });

    // Set new sort direction
    header.classList.add(isAsc ? 'desc' : 'asc');

    // Sort rows
    rows.sort((a, b) => {
      let aVal = a.cells[columnIndex]?.textContent.trim() || '';
      let bVal = b.cells[columnIndex]?.textContent.trim() || '';

      // Handle different types
      if (type === 'number') {
        aVal = parseFloat(aVal.replace(/[^0-9.-]/g, '')) || 0;
        bVal = parseFloat(bVal.replace(/[^0-9.-]/g, '')) || 0;
      } else if (type === 'date') {
        aVal = new Date(aVal).getTime() || 0;
        bVal = new Date(bVal).getTime() || 0;
      } else {
        aVal = aVal.toLowerCase();
        bVal = bVal.toLowerCase();
      }

      if (aVal < bVal) return isAsc ? 1 : -1;
      if (aVal > bVal) return isAsc ? -1 : 1;
      return 0;
    });

    // Re-append rows in sorted order
    rows.forEach(row => tbody.appendChild(row));
  }

  // Initialize sortable table headers
  function initSortableTables() {
    document.querySelectorAll('th.sortable').forEach(th => {
      th.addEventListener('click', function() {
        const table = this.closest('table');
        const columnIndex = Array.from(this.parentNode.children).indexOf(this);
        const type = this.dataset.sortType || 'string';
        sortTable(table, columnIndex, type);
      });
    });
  }

  // Filter table rows
  function filterTable(input, tableId) {
    const filter = input.value.toLowerCase();
    const table = document.getElementById(tableId);
    if (!table) return;

    const rows = table.querySelectorAll('tbody tr:not(.cluster-details)');
    rows.forEach(row => {
      const text = row.textContent.toLowerCase();
      row.style.display = text.includes(filter) ? '' : 'none';
    });
  }

  // Animate all risk gauges on load
  function animateRiskGauge() {
    document.querySelectorAll('.risk-gauge-fill').forEach((gauge, index) => {
      const targetOffset = parseFloat(gauge.dataset.targetOffset);
      if (isNaN(targetOffset)) return;
      setTimeout(() => {
        gauge.setAttribute('stroke-dashoffset', targetOffset);
      }, 300 + (index * 150)); // Stagger animation
    });
  }

  // Animate stat counters
  function animateCounters() {
    document.querySelectorAll('.stat-value[data-count]').forEach(counter => {
      const target = parseInt(counter.dataset.count);
      const duration = 1000;
      const step = target / (duration / 16);
      let current = 0;

      const timer = setInterval(() => {
        current += step;
        if (current >= target) {
          counter.textContent = target;
          clearInterval(timer);
        } else {
          counter.textContent = Math.floor(current);
        }
      }, 16);
    });
  }

  // Add click handler for expandable rows
  function initClickableRows() {
    document.querySelectorAll('tr[data-popup-id]').forEach(row => {
      // Prevent duplicate initialization
      if (row.dataset.clickInitialized) return;
      row.dataset.clickInitialized = 'true';

      row.classList.add('clickable');
      row.addEventListener('click', function(e) {
        // Prevent auto-popup within 200ms of tab switch
        if (Date.now() - lastTabSwitch < 200) return;

        if (e.target.tagName === 'A' || e.target.classList.contains('copy-icon')) return;
        const popupId = this.dataset.popupId;
        if (popupId) openPopup(popupId);
      });
    });
  }

  // Keyboard shortcuts
  document.addEventListener('keydown', function(e) {
    // Escape closes popups
    if (e.key === 'Escape') {
      closeAllPopups();
    }

    // Alt + 1/2/3 switches tabs
    if (e.altKey && ['1', '2', '3'].includes(e.key)) {
      e.preventDefault();
      const tabs = ['summary', 'userrisk', 'signins'];
      const tabIndex = parseInt(e.key) - 1;
      if (tabs[tabIndex]) showTab(tabs[tabIndex]);
    }
  });

  // Click outside popup to close (since overlay has pointer-events: none for scroll support)
  document.addEventListener('click', function(e) {
    const visiblePopup = document.querySelector('.popup.visible');
    if (visiblePopup && !visiblePopup.contains(e.target) && !e.target.closest('[data-popup-id]') && !e.target.closest('.clickable')) {
      closeAllPopups();
    }
  });

  // ========================================
  // FALSE POSITIVE MARKING FEATURE
  // ========================================

  // Get false positives from localStorage
  function getFalsePositives() {
    if (!window.reportData || !window.reportData.reportId) return { userRisk: [], signIns: [] };
    try {
      const stored = localStorage.getItem(window.reportData.reportId);
      if (stored) {
        return JSON.parse(stored);
      }
    } catch (e) {
      console.error('Error loading false positives:', e);
    }
    return { userRisk: [], signIns: [] };
  }

  // Save false positives to localStorage
  function saveFalsePositives(data) {
    if (!window.reportData || !window.reportData.reportId) return;
    try {
      localStorage.setItem(window.reportData.reportId, JSON.stringify(data));
    } catch (e) {
      console.error('Error saving false positives:', e);
    }
  }

  // Toggle false positive status for an item
  function toggleFalsePositive(type, id) {
    const fps = getFalsePositives();

    if (type === 'userRisk') {
      const index = fps.userRisk.indexOf(id);
      if (index > -1) {
        fps.userRisk.splice(index, 1);
      } else {
        fps.userRisk.push(id);
      }
    } else if (type === 'signIn') {
      const index = fps.signIns.indexOf(id);
      if (index > -1) {
        fps.signIns.splice(index, 1);
      } else {
        fps.signIns.push(id);
      }
    }

    saveFalsePositives(fps);
    applyFalsePositiveStyles();
    recalculateAndUpdateDisplay();
  }

  // Apply visual styles to false positive items
  function applyFalsePositiveStyles() {
    const fps = getFalsePositives();

    // Apply to user risk rows
    document.querySelectorAll('[data-indicator-id]').forEach(row => {
      const id = row.dataset.indicatorId;
      const btn = row.querySelector('.fp-toggle');
      if (fps.userRisk.includes(id)) {
        row.classList.add('false-positive');
        if (btn) btn.textContent = 'Unmark FP';
      } else {
        row.classList.remove('false-positive');
        if (btn) btn.textContent = 'Mark FP';
      }
    });

    // Apply to sign-in rows
    document.querySelectorAll('[data-signin-id]').forEach(row => {
      const id = row.dataset.signinId;
      const btn = row.querySelector('.fp-toggle');
      if (fps.signIns.includes(id)) {
        row.classList.add('false-positive');
        if (btn) btn.textContent = 'Unmark FP';
      } else {
        row.classList.remove('false-positive');
        if (btn) btn.textContent = 'Mark FP';
      }
    });
  }

  // Recalculate user risk score excluding false positives
  function recalculateUserRiskScore() {
    if (!window.reportData || !window.reportData.userRisk) return window.reportData?.userRisk || { score: 0, maxScore: 20 };

    const fps = getFalsePositives();
    let newScore = 0;

    window.reportData.userRisk.indicators.forEach(indicator => {
      if (indicator.applicable && !fps.userRisk.includes(indicator.id)) {
        newScore += indicator.points;
      }
    });

    return {
      score: newScore,
      maxScore: window.reportData.userRisk.maxScore
    };
  }

  // Recalculate breach probability excluding false positives
  function recalculateBreachProbability() {
    if (!window.reportData) return { percentage: 0, status: 'Unlikely', color: '#2cc29f' };

    const fps = getFalsePositives();

    // Check if all breach signals are marked as FP
    const breachSignals = window.reportData.riskSummary?.breachSignals || [];
    const allBreachSignalsFP = breachSignals.length > 0 && breachSignals.every(bs => isBreachSignalAllFP(bs.id));

    // Check if all config risks are marked as FP
    const configRisks = window.reportData.riskSummary?.configRisks || [];
    const allConfigRisksFP = configRisks.length > 0 && configRisks.every(cr => isConfigRiskAllFP(cr.id));

    // If all breach signals AND all config risks are FP, return 0%
    if (allBreachSignalsFP && allConfigRisksFP) {
      return { percentage: 0, status: 'Unlikely', color: '#2cc29f' };
    }

    // Initialize category scores (matching Get-BreachProbability in htmltools.ps1)
    const categories = {
      CredentialCompromise: { score: 0, maxScore: 40 },
      SessionAnomalies: { score: 0, maxScore: 35 },
      ConfigWeakness: { score: 0, maxScore: 20 },
      Temporal: { score: 0, maxScore: 5 }
    };

    let isAdmin = false;

    // If all breach signals are FP, skip credential compromise and session anomaly scoring
    const skipBreachScoring = allBreachSignalsFP;

    // Count remaining user risk indicators
    const activeUserRisks = (window.reportData.userRisk?.indicators || [])
      .filter(i => i.applicable && !fps.userRisk.includes(i.id));

    // Check for specific high-impact indicators
    activeUserRisks.forEach(indicator => {
      const name = indicator.name.toLowerCase();
      if (name.includes('no mfa')) {
        if (!allConfigRisksFP) categories.ConfigWeakness.score += 8;
      } else if (name.includes('recent mfa change')) {
        if (!skipBreachScoring) categories.CredentialCompromise.score += 10;
      } else if (name.includes('forwarding')) {
        if (!skipBreachScoring) categories.ConfigWeakness.score += 8;  // Forwarding is a breach signal
      } else if (name.includes('suspicious inbox')) {
        if (!skipBreachScoring) categories.ConfigWeakness.score += 4;  // Suspicious inbox is a breach signal
      } else if (name.includes('password reset')) {
        if (!skipBreachScoring) categories.CredentialCompromise.score += 8;
      } else if (name.includes('ca protection')) {
        if (!allConfigRisksFP) categories.ConfigWeakness.score += 6;
      } else if (name.includes('admin')) {
        isAdmin = true;
      }
    });

    // Count remaining sign-in risks
    const activeSignIns = (window.reportData.signIns || [])
      .filter(s => !fps.signIns.includes(s.id));

    // Analyze sign-ins for breach indicators (skip if all breach signals are FP)
    if (!skipBreachScoring) {
      activeSignIns.forEach(signin => {
        const breakdown = signin.breakdown || [];

        // Check for MFA failures
        if (breakdown.some(b => b.name && b.name.toLowerCase().includes('mfa') && b.name.toLowerCase().includes('fail'))) {
          categories.CredentialCompromise.score += 10;
        }

        // Check for impossible travel
        if (breakdown.some(b => b.name && b.name.toLowerCase().includes('impossible'))) {
          categories.SessionAnomalies.score += 8;
        }

        // Check for session anomalies
        if (breakdown.some(b => b.name && b.name.toLowerCase().includes('session'))) {
          categories.SessionAnomalies.score += 5;
        }

        // Check for country switches
        if (breakdown.some(b => b.name && b.name.toLowerCase().includes('country'))) {
          categories.SessionAnomalies.score += 3;
        }

        // High risk sign-in general contribution
        if (signin.score >= 7) {
          categories.CredentialCompromise.score += 5;
        }
      });
    }

    // Config risks from sign-ins (legacy protocols) - only if config risks not all FP
    if (!allConfigRisksFP) {
      activeSignIns.forEach(signin => {
        const breakdown = signin.breakdown || [];
        if (breakdown.some(b => b.name && (b.name.toLowerCase().includes('legacy') || b.name.toLowerCase().includes('imap') || b.name.toLowerCase().includes('pop')))) {
          categories.ConfigWeakness.score += 4;
        }
      });
    }

    // Cap each category at its max score
    Object.keys(categories).forEach(cat => {
      if (categories[cat].score > categories[cat].maxScore) {
        categories[cat].score = categories[cat].maxScore;
      }
    });

    // Calculate base percentage
    const totalScore = Object.values(categories).reduce((sum, cat) => sum + cat.score, 0);
    let basePercentage = totalScore;

    // Apply multipliers
    let multiplier = 1.0;

    // Credential indicator present (only if breach signals not all FP)
    if (!skipBreachScoring && categories.CredentialCompromise.score > 0) {
      multiplier *= 1.3;
    }

    // Admin account (only matters if there are active risks)
    if (isAdmin && !allConfigRisksFP) {
      multiplier *= 1.2;
    }

    // Multiple categories affected
    const affectedCategories = Object.values(categories).filter(cat => cat.score > 0).length;
    if (affectedCategories >= 3) {
      multiplier *= 1.15;
    }

    // Calculate final percentage (capped at 100)
    let percentage = Math.min(100, Math.round(basePercentage * multiplier));

    // If all breach signals are FP but there are still config risks, cap at lower value
    if (skipBreachScoring && !allConfigRisksFP && percentage > 20) {
      percentage = Math.min(percentage, 20);
    }

    // Determine status and color
    let status, color;
    if (percentage >= 71) {
      status = 'High Likelihood';
      color = '#8b0000';
    } else if (percentage >= 41) {
      status = 'Probable';
      color = '#dc3545';
    } else if (percentage >= 21) {
      status = 'Possible';
      color = '#f0ad4e';
    } else {
      status = 'Unlikely';
      color = '#2cc29f';
    }

    return { percentage, status, color };
  }

  // Get risk level and color from score
  function getRiskLevelFromScore(score) {
    if (score >= 10) return { level: 'Critical', color: '#8b0000' };
    if (score >= 7) return { level: 'High', color: '#dc3545' };
    if (score >= 4) return { level: 'Medium', color: '#f0ad4e' };
    return { level: 'Low', color: '#2cc29f' };
  }

  // Update all visual displays with recalculated values
  function recalculateAndUpdateDisplay() {
    const fps = getFalsePositives();
    const userRisk = recalculateUserRiskScore();
    const breachProb = recalculateBreachProbability();
    const riskInfo = getRiskLevelFromScore(userRisk.score);

    // Update Risk Score gauge
    const riskGauges = document.querySelectorAll('.risk-gauge');
    if (riskGauges[0]) {
      const scoreEl = riskGauges[0].querySelector('.risk-gauge-score');
      const fillEl = riskGauges[0].querySelector('.risk-gauge-fill');
      if (scoreEl) {
        scoreEl.textContent = userRisk.score;
        scoreEl.style.color = riskInfo.color;
      }
      if (fillEl) {
        const circumference = 339; // 2 * PI * 54
        const percentage = Math.min(100, Math.round((userRisk.score / userRisk.maxScore) * 100));
        const dashOffset = Math.round(circumference * (1 - (percentage / 100)));
        fillEl.style.stroke = riskInfo.color;
        fillEl.setAttribute('stroke-dashoffset', dashOffset);
      }
    }

    // Update Breach Probability gauge
    if (riskGauges[1]) {
      const scoreEl = riskGauges[1].querySelector('.risk-gauge-score');
      const fillEl = riskGauges[1].querySelector('.risk-gauge-fill');
      if (scoreEl) {
        scoreEl.textContent = breachProb.percentage + '%';
        scoreEl.style.color = breachProb.color;
      }
      if (fillEl) {
        const circumference = 339;
        const dashOffset = Math.round(circumference * (1 - (breachProb.percentage / 100)));
        fillEl.style.stroke = breachProb.color;
        fillEl.setAttribute('stroke-dashoffset', dashOffset);
      }
    }

    // Update risk level text in summary details
    const summaryDetails = document.querySelector('.summary-details');
    if (summaryDetails) {
      const riskLevelSpan = summaryDetails.querySelector('span[style*="color"]');
      if (riskLevelSpan && riskLevelSpan.textContent.includes('Risk')) {
        riskLevelSpan.textContent = riskInfo.level + ' Risk';
        riskLevelSpan.style.color = riskInfo.color;
      }

      // Update breach status text
      const breachStatusText = document.getElementById('breach-status-text');
      if (breachStatusText) {
        breachStatusText.textContent = breachProb.status;
        breachStatusText.style.color = breachProb.color;
      }

      // Update config issues indicator
      const configIndicator = document.getElementById('config-issues-indicator');
      if (configIndicator) {
        const configRisks = window.reportData.riskSummary?.configRisks || [];
        const activeConfigCount = configRisks.filter(cr => !isConfigRiskAllFP(cr.id)).length;
        if (activeConfigCount > 0) {
          configIndicator.textContent = ' • ' + activeConfigCount + ' config issue' + (activeConfigCount !== 1 ? 's' : '');
          configIndicator.style.display = '';
        } else {
          configIndicator.textContent = '';
          configIndicator.style.display = 'none';
        }
      }
    }

    // Update stat cards
    const statCards = document.querySelectorAll('.stat-card');
    statCards.forEach(card => {
      const label = card.querySelector('.stat-label');
      const value = card.querySelector('.stat-value');
      if (label && value) {
        const labelText = label.textContent.toLowerCase();
        if (labelText.includes('user risk')) {
          const activeCount = (window.reportData.userRisk?.indicators || [])
            .filter(i => i.applicable && !fps.userRisk.includes(i.id)).length;
          value.textContent = activeCount;
        } else if (labelText.includes('high risk')) {
          const highRiskCount = (window.reportData.signIns || [])
            .filter(s => !fps.signIns.includes(s.id) && s.score >= 7).length;
          value.textContent = highRiskCount;
        } else if (labelText.includes('sign-in')) {
          const activeSignIns = (window.reportData.signIns || [])
            .filter(s => !fps.signIns.includes(s.id)).length;
          value.textContent = activeSignIns;
        }
      }
    });

    // Update tab badges
    const userRiskBadge = document.querySelector('#tab-userrisk .tab-badge');
    if (userRiskBadge) {
      const activeCount = (window.reportData.userRisk?.indicators || [])
        .filter(i => i.applicable && !fps.userRisk.includes(i.id)).length;
      userRiskBadge.textContent = activeCount;
    }

    const signInBadge = document.querySelector('#tab-signins .tab-badge');
    if (signInBadge) {
      const activeCount = (window.reportData.signIns || [])
        .filter(s => !fps.signIns.includes(s.id)).length;
      signInBadge.textContent = activeCount;
    }

    // Update Risk Summary row styles (auto-strikethrough when all triggers are FP)
    updateRiskSummaryStyles();
  }

  // ========================================
  // RISK SUMMARY FALSE POSITIVE FUNCTIONS
  // ========================================

  // Check if all triggers for a breach signal are marked as FP
  function isBreachSignalAllFP(breachId) {
    const breach = window.reportData.riskSummary?.breachSignals?.find(b => b.id === breachId);
    if (!breach || !breach.triggerIds || breach.triggerIds.length === 0) return false;

    const fps = getFalsePositives();
    const fpList = breach.triggerType === 'signIn' ? fps.signIns : fps.userRisk;

    return breach.triggerIds.every(id => fpList.includes(id));
  }

  // Check if all triggers for a config risk are marked as FP
  function isConfigRiskAllFP(configId) {
    const config = window.reportData.riskSummary?.configRisks?.find(c => c.id === configId);
    if (!config || !config.triggerIds || config.triggerIds.length === 0) return false;

    const fps = getFalsePositives();
    const fpList = config.triggerType === 'signIn' ? fps.signIns : fps.userRisk;

    return config.triggerIds.every(id => fpList.includes(id));
  }

  // Apply FP styles to Risk Summary rows
  function updateRiskSummaryStyles() {
    // Breach signals
    document.querySelectorAll('[data-breach-id]').forEach(row => {
      const breachId = row.dataset.breachId;
      if (isBreachSignalAllFP(breachId)) {
        row.classList.add('false-positive');
      } else {
        row.classList.remove('false-positive');
      }
    });

    // Config risks
    document.querySelectorAll('[data-config-id]').forEach(row => {
      const configId = row.dataset.configId;
      if (isConfigRiskAllFP(configId)) {
        row.classList.add('false-positive');
      } else {
        row.classList.remove('false-positive');
      }
    });

    // Recommendations - strikethrough when linked breach/config is FP
    document.querySelectorAll('#recommendations-table tbody tr[data-linked-to]').forEach(row => {
      const linkedTo = row.dataset.linkedTo;
      const linkedType = row.dataset.linkedType;
      const canBeFP = row.dataset.canFp;

      // Items that cannot be FP should never be struck through
      if (canBeFP === 'false' || !linkedTo) {
        row.classList.remove('false-positive');
        return;
      }

      // Check if linked breach/config is all FP
      let isFP = false;
      if (linkedType === 'breach') {
        isFP = isBreachSignalAllFP(linkedTo);
      } else if (linkedType === 'config') {
        isFP = isConfigRiskAllFP(linkedTo);
      }

      if (isFP) {
        row.classList.add('false-positive');
      } else {
        row.classList.remove('false-positive');
      }
    });
  }

  // Find trigger details by type and ID
  function findTriggerDetails(type, id) {
    if (type === 'signIn') {
      const signin = window.reportData.signIns?.find(s => s.id === id);
      if (signin) {
        return { label: signin.time + ' - ' + signin.ip, popupId: signin.popupId };
      }
    } else if (type === 'userRisk') {
      const indicator = window.reportData.userRisk?.indicators?.find(i => i.id === id);
      if (indicator) {
        return { label: indicator.name };
      }
    }
    return { label: id };
  }

  // Show dynamic popup with content
  function showDynamicPopup(title, content) {
    // Create or reuse dynamic popup element
    let popup = document.getElementById('dynamic-popup');
    if (!popup) {
      popup = document.createElement('div');
      popup.id = 'dynamic-popup';
      popup.className = 'popup';
      popup.setAttribute('role', 'dialog');
      popup.setAttribute('aria-modal', 'true');
      popup.innerHTML = '<div class="popup-header"><h3></h3><button class="popup-close" onclick="closeDynamicPopup()" aria-label="Close dialog">&times;</button></div><div class="popup-body"></div>';
      document.body.appendChild(popup);
    }

    popup.querySelector('.popup-header h3').textContent = title;
    popup.querySelector('.popup-body').innerHTML = content;

    closeAllPopups();
    popup.classList.add('visible');
    popup.setAttribute('aria-hidden', 'false');
    document.getElementById('popup-overlay').classList.add('active');
    document.body.classList.add('popup-open');

    // Focus the close button
    popup.querySelector('.popup-close').focus();
  }

  // Close dynamic popup
  function closeDynamicPopup() {
    const popup = document.getElementById('dynamic-popup');
    if (popup) {
      popup.classList.remove('visible');
      popup.setAttribute('aria-hidden', 'true');
    }
    document.getElementById('popup-overlay')?.classList.remove('active');
    document.body.classList.remove('popup-open');
  }

  // Show popup with related triggers for breach signal
  function showBreachDetails(breachId) {
    const breach = window.reportData.riskSummary?.breachSignals?.find(b => b.id === breachId);
    if (!breach) return;

    const fps = getFalsePositives();
    const fpList = breach.triggerType === 'signIn' ? fps.signIns : fps.userRisk;

    let content = '<p style="margin-bottom: 1rem;"><strong>' + breach.triggerIds.length + '</strong> trigger(s) for this signal:</p>';
    content += '<table><thead><tr><th>Item</th><th>Status</th><th>Action</th></tr></thead><tbody>';

    breach.triggerIds.forEach(triggerId => {
      const isFP = fpList.includes(triggerId);
      const item = findTriggerDetails(breach.triggerType, triggerId);
      const rowClass = isFP ? 'class="false-positive"' : '';
      const statusText = isFP ? '<span style="color: var(--status-good);">Marked FP</span>' : '<span style="color: var(--status-warning);">Active</span>';
      content += '<tr ' + rowClass + '><td>' + item.label + '</td><td>' + statusText + '</td><td><a href="#" onclick="scrollToTrigger(\'' + breach.triggerType + '\', \'' + triggerId + '\'); return false;">View</a></td></tr>';
    });

    content += '</tbody></table>';
    content += '<p style="margin-top: 1rem; color: var(--text-muted); font-size: 0.85rem;">Mark all triggers as FP to cross out this signal.</p>';

    showDynamicPopup('Breach Signal: ' + breach.name, content);
  }

  // Show popup with related triggers for config risk
  function showConfigDetails(configId) {
    const config = window.reportData.riskSummary?.configRisks?.find(c => c.id === configId);
    if (!config) return;

    const fps = getFalsePositives();
    const fpList = config.triggerType === 'signIn' ? fps.signIns : fps.userRisk;

    let content = '<p style="margin-bottom: 1rem;"><strong>' + config.triggerIds.length + '</strong> trigger(s) for this risk:</p>';
    content += '<table><thead><tr><th>Item</th><th>Status</th><th>Action</th></tr></thead><tbody>';

    config.triggerIds.forEach(triggerId => {
      const isFP = fpList.includes(triggerId);
      const item = findTriggerDetails(config.triggerType, triggerId);
      const rowClass = isFP ? 'class="false-positive"' : '';
      const statusText = isFP ? '<span style="color: var(--status-good);">Marked FP</span>' : '<span style="color: var(--status-warning);">Active</span>';
      content += '<tr ' + rowClass + '><td>' + item.label + '</td><td>' + statusText + '</td><td><a href="#" onclick="scrollToTrigger(\'' + config.triggerType + '\', \'' + triggerId + '\'); return false;">View</a></td></tr>';
    });

    content += '</tbody></table>';
    content += '<p style="margin-top: 1rem; color: var(--text-muted); font-size: 0.85rem;">Mark all triggers as FP to cross out this risk.</p>';

    showDynamicPopup('Configuration Risk: ' + config.name, content);
  }

  // Scroll to and highlight a trigger row
  function scrollToTrigger(type, id) {
    closeDynamicPopup();
    closeAllPopups();

    // Switch to appropriate tab
    const tabId = type === 'signIn' ? 'signins' : 'userrisk';
    showTab(tabId);

    // Find and scroll to the row
    setTimeout(() => {
      const selector = type === 'signIn' ? '[data-signin-id="' + id + '"]' : '[data-indicator-id="' + id + '"]';
      const row = document.querySelector(selector);
      if (row) {
        row.scrollIntoView({ behavior: 'smooth', block: 'center' });
        row.classList.add('highlight');
        setTimeout(() => row.classList.remove('highlight'), 2000);
      }
    }, 150);
  }

  // Load and apply false positives on page load
  function initFalsePositives() {
    if (!window.reportData) return;
    applyFalsePositiveStyles();
    recalculateAndUpdateDisplay();
  }

  // Initialize click handlers for Risk Summary rows
  function initRiskSummaryClicks() {
    console.log('initRiskSummaryClicks called');

    // Breach signal rows
    const breachRows = document.querySelectorAll('[data-breach-id]');
    console.log('Found breach signal rows:', breachRows.length);
    breachRows.forEach(row => {
      row.style.cursor = 'pointer';  // Ensure cursor is pointer
      row.addEventListener('click', function(e) {
        console.log('Breach row clicked:', this.dataset.breachId);
        e.preventDefault();
        e.stopPropagation();
        const breachId = this.dataset.breachId;
        if (breachId) showBreachDetails(breachId);
      });
    });

    // Config risk rows (only those that CAN be marked as FP)
    const configRows = document.querySelectorAll('[data-config-id]:not([data-no-fp])');
    console.log('Found config risk rows:', configRows.length);
    configRows.forEach(row => {
      row.style.cursor = 'pointer';  // Ensure cursor is pointer
      row.addEventListener('click', function(e) {
        console.log('Config row clicked:', this.dataset.configId);
        e.preventDefault();
        e.stopPropagation();
        const configId = this.dataset.configId;
        if (configId) showConfigDetails(configId);
      });
    });

    console.log('Risk summary data:', window.reportData?.riskSummary);
  }

  // Initialize all enhancements on DOMContentLoaded
  document.addEventListener('DOMContentLoaded', function() {
    // Tab keyboard navigation
    document.querySelectorAll('nav[role="tablist"] button[role="tab"]').forEach(tab => {
      tab.addEventListener('keydown', handleTabKeydown);
    });

    // Initialize UI enhancements
    initSortableTables();
    initClickableRows();
    animateRiskGauge();
    animateCounters();

    // Initialize Risk Summary click handlers
    initRiskSummaryClicks();

    // Initialize false positive feature
    initFalsePositives();

    // Add fade-in animation to main content
    document.querySelector('main')?.classList.add('fade-in');
  });
  </script>
</head>
<body>
  <div id="popup-overlay" class="popup-overlay"></div>

"@

    # Generate unique report ID for localStorage (UPN + timestamp)
    $reportTimestampId = (Get-Date).ToString("yyyyMMdd-HHmmss")
    $sanitizedUpn = $UserPrincipalName -replace '[^a-zA-Z0-9@.]', ''
    $reportId = "rut-fp-$sanitizedUpn-$reportTimestampId"

    # Calculate summary statistics for Executive Summary
    $userRiskCount = 0
    $signInRiskCount = 0
    $highRiskCount = 0
    $breachSignalCount = 0
    $configRiskCount = 0

    if ($global:aiadvisory.UserRisk -and $global:aiadvisory.UserRisk.Risks) {
        $userRiskCount = @($global:aiadvisory.UserRisk.Risks | Where-Object { $_.Details -eq "Applicable" }).Count
    }
    if ($global:aiadvisory.SignInRisk -and $global:aiadvisory.SignInRisk.SignIns) {
        $signInRiskCount = $global:aiadvisory.SignInRisk.SignIns.Count
        $highRiskCount = @($global:aiadvisory.SignInRisk.SignIns | Where-Object { $_.RiskLevel -in @("High", "Critical") }).Count
    }
    if ($global:aiadvisory.RiskSummary) {
        $breachSignalCount = @($global:aiadvisory.RiskSummary.BreachSignals).Count
        $configRiskCount = @($global:aiadvisory.RiskSummary.ConfigRisks).Count
    }

    # Use actual risk score from user risk analysis
    $overallScore = if ($global:aiadvisory.UserRisk -and $global:aiadvisory.UserRisk.RiskScore) {
        $global:aiadvisory.UserRisk.RiskScore
    } else { 0 }
    $maxGaugeScore = if ($global:aiadvisory.UserRisk -and $global:aiadvisory.UserRisk.MaxScore) {
        $global:aiadvisory.UserRisk.MaxScore
    } else { 20 }
    $gaugePercentage = [math]::Min(100, [math]::Round(($overallScore / $maxGaugeScore) * 100))

    # Determine risk level and color (thresholds based on actual score)
    $overallRiskLevel = switch ($true) {
        { $overallScore -ge 10 } { "Critical"; break }
        { $overallScore -ge 7 }  { "High"; break }
        { $overallScore -ge 4 }  { "Medium"; break }
        default { "Low" }
    }

    $riskColor = switch ($overallRiskLevel) {
        "Critical" { "#8b0000" }
        "High"     { "#dc3545" }
        "Medium"   { "#f0ad4e" }
        default    { "#2cc29f" }
    }


    # Calculate SVG arc values (circumference = 2 * PI * radius)
    $radius = 54
    $circumference = [math]::Round(2 * [math]::PI * $radius)
    $dashOffset = [math]::Round($circumference * (1 - ($gaugePercentage / 100)))

    # Calculate Breach Probability
    $breachProb = Get-BreachProbability
    $breachPercentage = $breachProb.Percentage
    $breachStatus = $breachProb.Status
    $breachColor = $breachProb.Color
    $breachDashOffset = [math]::Round($circumference * (1 - ($breachPercentage / 100)))

    # Store breach probability in global advisory for Risk Summary
    $global:aiadvisory.BreachProbability = $breachProb

    # Build user risk indicators JSON for false positive feature
    # Sort risks by points (descending) then by name to match the display order in userrisk.ps1
    $userRiskIndicatorsJson = @()
    $indicatorIdCounter = 1
    if ($global:aiadvisory.UserRisk -and $global:aiadvisory.UserRisk.Risks) {
        $sortedRisks = $global:aiadvisory.UserRisk.Risks | Sort-Object -Property @{ Expression = { $_.Points }; Descending = $true }, @{ Expression = { $_.Type }; Descending = $false }
        foreach ($risk in $sortedRisks) {
            $indicatorId = "ur-" + $indicatorIdCounter.ToString("00")
            $indicatorIdCounter++
            $applicable = if ($risk.Details -eq "Applicable") { "true" } else { "false" }
            # Use actual points from the risk data
            $points = if ($risk.Points) { $risk.Points } else { 0 }
            $maxPoints = if ($risk.MaxPoints) { $risk.MaxPoints } else { $points }
            $safeName = $risk.Type -replace "'", "\'"
            $userRiskIndicatorsJson += "        { `"id`": `"$indicatorId`", `"name`": `"$safeName`", `"points`": $points, `"maxPoints`": $maxPoints, `"applicable`": $applicable }"
        }
    }
    $userRiskIndicatorsJsonStr = $userRiskIndicatorsJson -join ",`n"

    # Build sign-in data JSON for false positive feature
    $signInsJson = @()
    if ($global:aiadvisory.SignInRisk -and $global:aiadvisory.SignInRisk.SignIns) {
        foreach ($signin in $global:aiadvisory.SignInRisk.SignIns) {
            $safeTime = "$($signin.Time)" -replace "'", "\'" -replace '"', '\"'
            $safeIp = "$($signin.IP)" -replace "'", "\'" -replace '"', '\"'
            $signInScore = if ($signin.Score) { $signin.Score } else { 0 }
            $riskLevel = if ($signin.RiskLevel) { $signin.RiskLevel } else { "Low" }

            # Build breakdown array with actual points
            $breakdownItems = @()
            if ($signin.RiskFactors) {
                foreach ($factor in $signin.RiskFactors) {
                    if ($factor.Details -eq "Applicable") {
                        $safeName = "$($factor.Type)" -replace "'", "\'" -replace '"', '\"'
                        $factorPoints = if ($factor.Points) { $factor.Points } else { 1 }
                        $breakdownItems += "          { `"name`": `"$safeName`", `"points`": $factorPoints }"
                    }
                }
            }
            $breakdownStr = $breakdownItems -join ",`n"

            # Use ID from stored data, or generate if not available
            $signInId = if ($signin.Id) { $signin.Id } else { "si-" + ("$($signin.Time)$($signin.IP)").GetHashCode().ToString("X8") }
            $popupId = if ($signin.PopupId) { $signin.PopupId } else { "" }

            $signInsJson += @"
      {
        "id": "$signInId",
        "popupId": "$popupId",
        "time": "$safeTime",
        "ip": "$safeIp",
        "score": $signInScore,
        "riskLevel": "$riskLevel",
        "breakdown": [
$breakdownStr
        ]
      }
"@
        }
    }
    $signInsJsonStr = $signInsJson -join ",`n"

    # Build breach probability categories JSON
    $breachCategoriesJson = @()
    if ($breachProb -and $breachProb.Categories) {
        foreach ($catName in $breachProb.Categories.Keys) {
            $cat = $breachProb.Categories[$catName]
            $breachCategoriesJson += "        `"$catName`": { `"score`": $($cat.Score), `"maxScore`": $($cat.MaxScore) }"
        }
    }
    $breachCategoriesJsonStr = $breachCategoriesJson -join ",`n"

    # Build risk summary JSON for breach signals and config risks
    $breachSignalsJson = @()
    $configRisksJson = @()
    if ($global:aiadvisory.RiskSummary) {
        # Breach signals
        foreach ($breach in $global:aiadvisory.RiskSummary.BreachSignals) {
            $triggerIdsArray = ($breach.TriggerIds | ForEach-Object { "`"$_`"" }) -join ", "
            $safeName = $breach.Signal -replace "'", "\'" -replace '"', '\"'
            $breachSignalsJson += @"
        {
          "id": "$($breach.Id)",
          "name": "$safeName",
          "severity": "$($breach.Severity)",
          "triggerType": "$($breach.TriggerType)",
          "triggerIds": [$triggerIdsArray]
        }
"@
        }
        # Config risks
        foreach ($config in $global:aiadvisory.RiskSummary.ConfigRisks) {
            $triggerIdsArray = ($config.TriggerIds | ForEach-Object { "`"$_`"" }) -join ", "
            $safeName = $config.Risk -replace "'", "\'" -replace '"', '\"'
            # Default canBeFP to true if not specified
            $canBeFP = if ($null -eq $config.CanBeFP) { "true" } else { "$($config.CanBeFP)".ToLower() }
            $configRisksJson += @"
        {
          "id": "$($config.Id)",
          "name": "$safeName",
          "impact": "$($config.Severity)",
          "triggerType": "$($config.TriggerType)",
          "triggerIds": [$triggerIdsArray],
          "canBeFP": $canBeFP
        }
"@
        }
    }
    $breachSignalsJsonStr = $breachSignalsJson -join ",`n"
    $configRisksJsonStr = $configRisksJson -join ",`n"

    $html += @"

  <!-- Report Data for False Positive Feature -->
  <script>
  window.reportData = {
    reportId: "$reportId",
    userRisk: {
      score: $overallScore,
      maxScore: $maxGaugeScore,
      indicators: [
$userRiskIndicatorsJsonStr
      ]
    },
    signIns: [
$signInsJsonStr
    ],
    breachProbability: {
      percentage: $breachPercentage,
      categories: {
$breachCategoriesJsonStr
      }
    },
    riskSummary: {
      breachSignals: [
$breachSignalsJsonStr
      ],
      configRisks: [
$configRisksJsonStr
      ]
    }
  };
  </script>

  <!-- Executive Summary Card -->
  <div class="executive-summary" style="grid-template-columns: auto auto 1fr auto;">
    <div class="risk-gauge">
      <svg viewBox="0 0 120 120">
        <circle class="risk-gauge-bg" cx="60" cy="60" r="$radius"></circle>
        <circle class="risk-gauge-fill" cx="60" cy="60" r="$radius"
                stroke="$riskColor"
                stroke-dasharray="$circumference"
                stroke-dashoffset="$circumference"
                data-target-offset="$dashOffset"></circle>
      </svg>
      <div class="risk-gauge-text">
        <div class="risk-gauge-score" style="color: $riskColor;">$overallScore</div>
        <div class="risk-gauge-label">Risk Score</div>
      </div>
    </div>

    <div class="risk-gauge" title="Breach Probability: Likelihood of actual credential compromise">
      <svg viewBox="0 0 120 120">
        <circle class="risk-gauge-bg" cx="60" cy="60" r="$radius"></circle>
        <circle class="risk-gauge-fill" cx="60" cy="60" r="$radius"
                stroke="$breachColor"
                stroke-dasharray="$circumference"
                stroke-dashoffset="$circumference"
                data-target-offset="$breachDashOffset"></circle>
      </svg>
      <div class="risk-gauge-text">
        <div class="risk-gauge-score" style="color: $breachColor;">$breachPercentage%</div>
        <div class="risk-gauge-label">Breach Prob.</div>
      </div>
    </div>

    <div class="summary-details">
      <h2>Risky User Troubleshooter</h2>
      <div style="display: flex; flex-direction: column; gap: 0.25rem; margin-top: 0.5rem;">
        <div style="font-size: 0.95rem;">
          <span style="color: $riskColor;">$overallRiskLevel Risk</span>
        </div>
        <div style="font-size: 0.95rem;">
          <span id="breach-status-text" style="color: $breachColor;">$breachStatus</span>
          <span id="config-issues-indicator" style="color: var(--text-muted); font-size: 0.85rem;">$(if ($configRiskCount -gt 0) { " • $configRiskCount config issue$(if ($configRiskCount -ne 1) { 's' })" } else { '' })</span>
        </div>
        <div style="font-size: 0.95rem;">
          <span class="copy-inline">$UserPrincipalName <span class="copy-icon" onclick="copyValue('$UserPrincipalName', this)" title="Copy UPN">⧉</span></span>
        </div>
      </div>
    </div>

    <div class="quick-stats">
      <div class="stat-card">
        <div class="stat-value" data-count="$userRiskCount">0</div>
        <div class="stat-label">User Risks</div>
      </div>
      <div class="stat-card">
        <div class="stat-value" data-count="$signInRiskCount">0</div>
        <div class="stat-label">Sign-in Events</div>
      </div>
      <div class="stat-card">
        <div class="stat-value" data-count="$highRiskCount">0</div>
        <div class="stat-label">High Risk Sign-ins</div>
      </div>
    </div>
  </div>

  <nav role="tablist" aria-label="Report sections">
    <button role="tab" id="tab-summary" aria-controls="summary" aria-selected="true" tabindex="0" onclick="showTab('summary')">
      Risk Summary
    </button>
    <button role="tab" id="tab-userrisk" aria-controls="userrisk" aria-selected="false" tabindex="-1" onclick="showTab('userrisk')">
      User Risk
      <span class="tab-badge">$userRiskCount</span>
    </button>
    <button role="tab" id="tab-signins" aria-controls="signins" aria-selected="false" tabindex="-1" onclick="showTab('signins')">
      Sign-ins
      <span class="tab-badge">$signInRiskCount</span>
    </button>
  </nav>

  <main id="main-content">
    <div id="summary" role="tabpanel" aria-labelledby="tab-summary" aria-label="Risk Summary" class="tab-content active" aria-hidden="false">
      $summaryHtml
    </div>

    <div id="userrisk" role="tabpanel" aria-labelledby="tab-userrisk" aria-label="User Risk Analysis" class="tab-content" aria-hidden="true">
      $userRiskHtml
    </div>

    <div id="signins" role="tabpanel" aria-labelledby="tab-signins" aria-label="Sign-in Analysis" class="tab-content" aria-hidden="true">
"@

    # Log AbuseIPDB API key warning flag
    # Only show warning if feature was intended to be enabled but key loading failed
    $config = Get-Configuration
    $abuseIntendedEnabled = $false
    if ($config.apiKeys -and $config.apiKeys.abuseipdb) {
        $abuseIntendedEnabled = $config.apiKeys.abuseipdb.enabled -eq $true
    }
    $abuseFlag = $abuseIntendedEnabled -and ($global:ABUSEIPDB_APIKEY_WARNING -as [bool])
    Write-Log -Type "Information" -Message "AbuseIPDB: IntendedEnabled=$abuseIntendedEnabled, Warning=$($global:ABUSEIPDB_APIKEY_WARNING), ShowWarning=$abuseFlag"

    if ($abuseFlag) {
        $html += @"
      <div class='warning' role="alert">
        <h4>AbuseIPDB Reputation Check Skipped</h4>
        <p>
          AbuseIPDB was enabled but the API key could not be loaded.<br>
          All IP reputation scores were set to <code>0</code>, which may underestimate the actual risk.
        </p>
      </div>
"@
    }

    # Append sign-in section
    $html += $signInHtml

    # Final HTML close with footer
    $html += @"
    </div>
  </main>

  <footer>
    <p>
      Generated by <a href="https://github.com/VirtualiteNL" target="_blank" rel="noopener">Virtualite.nl</a> |
      Report for: $UserPrincipalName |
      Generated on: $reportTimestamp
    </p>
    <p>
      <button onclick="window.print()" class="copy-btn" style="margin: 0;">Print / Export to PDF</button>
    </p>
  </footer>
</body>
</html>
"@

    # Save the HTML report
    try {
        $html | Out-File -FilePath $OutputPath -Encoding UTF8
        Write-Log -Type "OK" -Message "HTML report successfully written to: $OutputPath"
        Write-Host "HTML report created: $OutputPath" -ForegroundColor Green

        # Automatically open the report in the default browser
        try {
            if ($IsMacOS) {
                Start-Process "open" -ArgumentList $OutputPath
            } elseif ($IsWindows) {
                Start-Process $OutputPath
            } elseif ($IsLinux) {
                Start-Process "xdg-open" -ArgumentList $OutputPath
            } else {
                # Fallback for Windows PowerShell 5.x (no $IsWindows variable)
                Start-Process $OutputPath
            }
            Write-Log -Type "Information" -Message "Report opened in default browser"
        } catch {
            Write-Log -Type "Alert" -Message "Could not auto-open report: $($_.Exception.Message)"
        }
    } catch {
        Write-Log -Type "Error" -Message "Failed to write HTML report: $($_.Exception.Message)"
        Write-Host "Failed to write HTML report. Check permissions or path." -ForegroundColor Red
    }
}
