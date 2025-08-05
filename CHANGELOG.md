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
