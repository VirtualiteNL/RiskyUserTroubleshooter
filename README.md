# 🛡️ Risky User Troubleshooter

A modular PowerShell-based tool to investigate potentially compromised or high-risk Microsoft 365 (Entra ID / Azure AD) user accounts. It analyzes user configuration and sign-in activity, calculates risk scores based on Indicators of Compromise (IOCs), and generates a Fluent UI-style HTML dashboard report — including optional OpenAI-powered advisory.

[![License: BY-NC-SA 4.0](https://img.shields.io/badge/license-Custom%20Non--Commercial-yellow.svg)](LICENSE.md)
![PowerShell](https://img.shields.io/badge/PowerShell-7+-blue)

---

## 📖 Overview

Risky User Troubleshooter connects to Microsoft Graph and Exchange Online, collects user and sign-in data, evaluates potential security risks using multiple IOCs, and outputs a user-friendly HTML dashboard.

### 🔍 Key Features

- **Interactive HTML Dashboard**: Collapsible, tab-based report in Fluent UI style.
- **Sign-In Risk Analysis**: Enriches each session with location, ASN, MFA/CA outcomes, and risk score.
- **User Account Risk Checks**: Checks admin roles, MFA settings, mailbox forwarding, etc.
- **AbuseIPDB Integration**: IP reputation checks using AbuseIPDB API (optional).
- **OpenAI Advisory**: AI-generated textual summary using ChatGPT API (optional).
- **Modular Design**: Each IOC is implemented as a separate module.
- **Comprehensive Logging**: Logs alerts, safe checks, info and errors to a TXT file.

---

## 📋 Requirements

- PowerShell 7+ (Windows)
- Microsoft 365 account with `Security Reader`, `Global Reader`, or higher permissions
- Required modules (auto-installed if missing):
  - Microsoft.Graph.Authentication
  - Microsoft.Graph.Identity.SignIns
  - Microsoft.Graph.Users / Groups / Applications
  - ExchangeOnlineManagement
- Internet connectivity
- (Optional) AbuseIPDB API key
- (Optional) OpenAI API key (ChatGPT access)

---

## ⚙️ Installation

# Clone the repository or download and extract ZIP
git clone https://github.com/YourName/RiskyUserTroubleshooter.git

# Optionally configure API keys
notepad .\api\apikey_openai.ps1
notepad .\api\apikey_abuseipdb.ps1

# Install required modules (or let script auto-install)
Install-Module Microsoft.Graph -Scope CurrentUser
Install-Module ExchangeOnlineManagement -Scope CurrentUser

# Optional: unblock the script if downloaded from the internet
Unblock-File .\riskyusertroubleshooter.ps1
```ps1
set-execution Bypass
```

---

## ▶️ Usage

### Interactive

```ps1
set-execution Bypass
```
```ps1
.\riskyusertroubleshooter.ps1
```

Enter the UPN (email) of the user to investigate when prompted.

### Non-interactive

```ps1
powershell -ExecutionPolicy Bypass -File .\riskyusertroubleshooter.ps1 user@example.com
```

> Authentication for Graph and Exchange Online will still prompt interactively.

---

## 📊 Example Output

An example report is included as `example.html`. It contains:

- AI-generated advisory summary
- User risk table (forwarding rules, role usage, etc.)
- Sign-in risk table with detailed session context and IOC triggers
- Risk scores and interactive pop-ups

---

## ⚠️ Indicators of Compromise (IOCs)

The tool checks for and scores events based on:

1. Untrusted IP/ASN (e.g. AbuseIPDB score > 70)
2. Odd-hour sign-ins (e.g. 02:00–05:00)
3. Sign-ins from unusual or high-risk geolocations
4. Impossible travel between logins
5. MFA anomalies or bypasses
6. Conditional Access bypass or failures
7. Legacy protocols usage (IMAP, POP, SMTP)
8. Suspicious OAuth consents
9. User flagged by Identity Protection
10. Privileged role assignments
11. Device ID/session mismatches
12. Shared IP between users
13. Unexpected app category usage
14. Signs of session hijacking

Each IOC increases the user or sign-in risk score and is visualized in the HTML report.

---

## 🧑‍⚖️ License

This project is under a **custom non-commercial license**:

- 🔓 Free for internal organizational use
- 🛠️ You may adapt and share under attribution
- 🚫 No commercial use without permission

See [`LICENSE.md`](LICENSE.md) for full terms.
