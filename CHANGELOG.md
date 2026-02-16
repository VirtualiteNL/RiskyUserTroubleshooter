# 🆕 Version 3.0.0 – Changelog

## 🎯 False Positive Management

- **Mark Individual Indicators as False Positive**
  Analysts can now mark individual sign-ins and user risk indicators as false positives directly in the report. FP-marked items are visually crossed out and excluded from risk calculations.

- **Persistent FP State**
  False positive markings are stored in localStorage and persist across browser sessions.

- **FP Summary in Risk Cards**
  Risk summary cards show which triggers are marked as FP with visual indicators.

## 🔒 Trusted IP Detection Fixes

- **SR-17 Named Location Fix**
  Fixed error when tenant has no CA Named Locations configured. Empty TrustedRanges parameter now handled correctly.

- **SR-18/SR-19 MFA Detection Improvement**
  Improved MFA success detection to check `AuthenticationRequirement` property and multiple authentication factors, not just `AuthenticationDetails.Count`.

- **Debug Logging for IP Statistics**
  Added summary logging showing how many IPs have MFA/compliant device sign-ins for troubleshooting.

## 🔐 MFA Change Detection Enhancement

- **Expanded Audit Log Filter**
  Now detects MFA changes matching:
  - "Authentication Method" (original)
  - "security info" (User registered security info)
  - "Authenticator" (User registered Authenticator App)
  - "StrongAuthentication" (Azure MFA service updates)
  - Category "Authentication Methods" as fallback

## 🎨 UI/UX Improvements

- **Similar Sign-Ins Dark Theme**
  Fixed similar sign-ins collapsible table to match dark theme styling using CSS variables.

- **User Risk Popup Fixes**
  Fixed popup content generation using hashtable lookup for consistent display.

- **Scroll Improvements**
  Fixed popup scrolling issues with proper overflow handling.

## 🐛 Bug Fixes

- Fixed user risk score display in summary cards
- Fixed CA Protection and OAuth Consents preservation in user risk data
- Softened language in risk descriptions to indicate possibility rather than certainty
- Various HTML/CSS consistency improvements

---

# 🆕 Version 2.3.0 – Changelog

## 🐛 UI Bug Fixes

- **Dubbele Risk Level tekst opgelost**
  Verwijderd CSS `::before` pseudo-elementen die "OK ", "WARN ", "HIGH ", "CRITICAL " prefixes toevoegden, waardoor dubbele tekst verscheen zoals "HIGH High Risk".

- **Executive Summary tekst gecorrigeerd**
  Gewijzigd van "$RiskLevel Risk Level" naar "$RiskLevel Risk" voor consistente weergave.

- **Timeline details tekst gecorrigeerd**
  Verwijderd dubbele "Risk" suffix in sign-in timeline weergave.

## 📊 IOC Scoring Verbeteringen

### User Risk IOCs (UR-01 t/m UR-10)
- **UR-01 No MFA Registered**: 2 → **3** punten (kritiek beveiligingsrisico)
- **UR-04 Forwarding Enabled**: 2 → **3** punten (hoog exfiltratierisico)
- **UR-05 Suspicious Inbox Rules**: 1 → **2** punten (auto forward/delete)
- **UR-07 Active Admin Role**: 1 → **2** punten (verhoogde privileges)

### Sign-In Risk IOCs (SR-01 t/m SR-15)
- **SR-01 Legacy Protocol**: 2 → **3** punten (geen MFA mogelijk)
- **SR-03 No MFA Used**: 1 → **2** punten (onbeschermde login)
- **SR-06 Suspicious IP+ASN**: 2 → **3** punten (hoge abuse + onbekende ASN)
- **SR-09 Session Anomaly**: 5 → **4** punten (gebalanceerd)
- **SR-15 Location Netherlands**: -2 → **-1** punten (minder impact)

## 🎯 Herziene Drempelwaarden

Alle modules gebruiken nu consistente risk level thresholds:
- **Critical**: Score ≥ 10
- **High**: Score ≥ 7
- **Medium**: Score ≥ 4
- **Low**: Score ≥ 1

## 📈 Verbeterde Executive Summary Berekening

Nieuwe formule voor overall risk score:
```
Overall Score = (User Risks × 2) + (High Risk Sign-Ins × 4) + min(Sign-In Count, 3)
```

## 📚 Documentatie

- **Nieuwe IOC-Scoring-Reference.md**
  Uitgebreide documentatie van alle IOCs, puntentoekenning en scoreberekening in `docs/IOC-Scoring-Reference.md`.

- **Gecentraliseerde configuratie**
  IOC definities en thresholds toegevoegd aan `config/settings.json` voor eenvoudiger beheer.

---

# 🆕 Version 2.2.0 – Changelog
** 🧭 User Experience & UI Enhancements **

🪟 Improved Popup Behavior
Only one popup is shown at a time. Clicking outside a popup now automatically closes it for a cleaner user experience.

🔍 Reporting & Data Improvements
🔐 OAuth Consents Show More Relevant Info
The OAuth section now highlights the most relevant risk attributes per app, including key permission scopes and app risk classification. Clutter and noise have been reduced.

👥 Multi-User Support
➕ Process Multiple UPNs in a Single Run
You can now investigate multiple users by entering comma-separated UPNs at the start of the script. A full HTML report is generated for each account, using a single Microsoft 365 connection session.


# 🆕 Version 2.1.0 – Changelog

## 🔐 New Indicators of Compromise (IOCs)

- 🛡️ **Conditional Access Evaluation**  
  Detects whether the user is effectively protected by Conditional Access policies enforcing MFA or compliant devices.

- ⚖️ **OAuth App Consents with Risk Classification**  
  Granted applications are now classified as **Low**, **Medium**, or **High risk**, based on consent type, context tags, and granted permissions.

## 🧰 Internal Improvements & Structure

- 🧱 **Unified Logging Format**  
  All `Write-Log` output now follows a consistent format with emojis, clear severity levels, and improved readability.

- 🖥️ **Improved Console Output (`Write-Host`)**  
  Console messages now use color coding and clear symbols to guide the analyst during script execution and debugging.

- 🧼 **Refactors and UI Consistency**  
  Tables, JSON exports, and popups have been restructured for better alignment, formatting, and HTML consistency across the report.
