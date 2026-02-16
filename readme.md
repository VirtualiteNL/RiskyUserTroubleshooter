# Risky User Troubleshooter

A modular PowerShell-based tool to investigate potentially compromised or high-risk Microsoft 365 (Entra ID / Azure AD) user accounts. It analyzes user configuration and sign-in activity, calculates risk scores based on Indicators of Compromise (IOCs), and generates a Fluent UI-style HTML dashboard report.

[![License: BY-NC-SA 4.0](https://img.shields.io/badge/license-Custom%20Non--Commercial-yellow.svg)](LICENSE.md)
![PowerShell](https://img.shields.io/badge/PowerShell-7+-blue)

---

## Overview

Risky User Troubleshooter connects to Microsoft Graph and Exchange Online, collects user and sign-in data, evaluates potential security risks using multiple IOCs, and outputs a user-friendly HTML dashboard.

### Key Features

- **Interactive HTML Dashboard**: Collapsible, tab-based report in Fluent UI style with full accessibility support (ARIA)
- **Sign-In Risk Analysis**: Enriches each session with location, ASN, MFA/CA outcomes, and risk score (19 indicators)
- **User Account Risk Checks**: Checks admin roles, MFA settings, mailbox forwarding, etc. (10 indicators)
- **Trusted IP Recognition**: Detects sign-ins from CA Named Locations and frequently used IPs
- **AbuseIPDB Integration**: IP reputation checks using AbuseIPDB API (optional)
- **Modular Design**: Each IOC is implemented as a separate module
- **Comprehensive Logging**: Configurable log levels with optional JSON output
- **Batch Processing**: Process multiple users with progress tracking and error recovery
- **Mobile-Responsive**: HTML reports work on all devices with print/PDF export support
- **Configuration File**: Centralized settings via JSON configuration

---

## What's New (v3.0)

### False Positive Management

- **Mark Indicators as FP**: Analysts can mark individual sign-ins and user risk indicators as false positives directly in the HTML report
- **Persistent State**: FP markings stored in localStorage, persist across browser sessions
- **Visual Feedback**: FP-marked items are crossed out and excluded from risk calculations

### Trusted IP Detection

- **SR-17 Fix**: Fixed error when tenant has no CA Named Locations
- **SR-18/SR-19 Improvement**: Better MFA detection using `AuthenticationRequirement` property
- **Debug Logging**: Summary shows IPs with MFA/compliant device sign-ins

### MFA Change Detection

- **Expanded Filter**: Now detects "security info", "Authenticator", and "StrongAuthentication" audit events

### UI/UX

- **Dark Theme Consistency**: Similar sign-ins table now matches dark theme
- **Popup Fixes**: Fixed scrolling and content display issues

---

## Requirements

- PowerShell 7+ (Windows, macOS, Linux)
- Microsoft 365 account with `Security Reader`, `Global Reader`, or higher permissions
- Required modules (auto-installed if missing):
  - Microsoft.Graph.Authentication
  - Microsoft.Graph.Identity.SignIns
  - Microsoft.Graph.Users / Groups / Applications
  - ExchangeOnlineManagement
- Internet connectivity
- (Optional) AbuseIPDB API key

---

## Installation

```powershell
# Clone the repository or download and extract ZIP
git clone https://github.com/VirtualiteNL/RiskyUserTroubleshooter.git
cd RiskyUserTroubleshooter

# Optionally configure AbuseIPDB API key (create _local version for private key)
Copy-Item .\api\apikey_abuseipdb.ps1 .\api\apikey_abuseipdb_local.ps1
# Edit the _local file with your API key

# Install required modules (or let script auto-install)
Install-Module Microsoft.Graph -Scope CurrentUser
Install-Module ExchangeOnlineManagement -Scope CurrentUser

# Optional: unblock the script if downloaded from the internet
Unblock-File .\riskyusertroubleshooter.ps1
```

---

## Configuration

The tool uses `config/settings.json` for configuration. Key settings:

```json
{
    "lookbackDays": 30,
    "auditLogGroupingThreshold": 10,
    "newAccountThresholdDays": 7,
    "impossibleTravelSpeedKmh": 1000,
    "abuseIpDbRiskThreshold": 70,
    "riskThresholds": {
        "critical": 10,
        "high": 7,
        "medium": 4,
        "low": 1
    },
    "logging": {
        "level": "Information",
        "enableDebug": false,
        "enableStructuredJson": false
    }
}
```

---

## Usage

### Interactive (Single or Multiple Users)

```powershell
.\riskyusertroubleshooter.ps1
# Enter UPN(s) when prompted: user1@example.com, user2@example.com
```

### Batch Processing

Enter comma-separated UPNs when prompted:
```
user1@contoso.com, user2@contoso.com, user3@contoso.com
```

The tool will:
1. Validate all UPNs
2. Process each user with progress indicator
3. Continue if one user fails
4. Show summary at the end

### Output

Reports are saved to:
- `reports/incidentreport-{upn}.html` - HTML dashboard
- `logs/incidentreport-{upn}.txt` - Detailed log file

---

## Indicators of Compromise (IOCs)

### Sign-In Risk Indicators (SR-01 to SR-19)

| ID | Indicator | Points | Description |
|----|-----------|--------|-------------|
| SR-01 | Legacy Protocol | +3 | IMAP/POP/SMTP usage (no MFA possible) |
| SR-02 | MFA Failure | +3 | Password correct, MFA failed |
| SR-03 | No MFA Used | +2 | Sign-in without MFA |
| SR-04 | CA Policy Failure | +2 | Conditional Access violation |
| SR-05 | Foreign IP | +1 to +3 | Non-NL location (scaled by abuse score) |
| SR-06 | Suspicious IP+ASN | +3 | High abuse score + unknown ASN |
| SR-07 | Impossible Travel | +4 | Geographically impossible travel |
| SR-08 | Outside Hours | +1 | Sign-in outside working hours |
| SR-09 | Session Anomaly | +4 | IP/device/country mismatch in session |
| SR-10 | Country Switch | +2 | Country changed during session |
| SR-11 | Multiple IPs | +1 | Multiple IPs in same session |
| SR-12 | Device Change | +1 | Browser/OS switch during session |
| SR-13 | Trusted Device | **-2** | Azure AD joined device |
| SR-14 | Compliant Device | **-3** | Intune compliant device |
| SR-15 | Netherlands | **-1** | Sign-in from expected location |
| SR-16 | Microsoft Risk | +2 to +4 | Identity Protection signals (P2) |
| SR-17 | Trusted Location IP | **-2** | IP in CA Named Location |
| SR-18 | Frequent IP (MFA) | **-1** | IP used 3+ times with MFA |
| SR-19 | Frequent IP (Compliant) | **-2** | IP used 3+ times with compliant device |

### User Risk Indicators (UR-01 to UR-10)

| ID | Indicator | Points | Description |
|----|-----------|--------|-------------|
| UR-01 | No MFA Registered | +3 | No MFA methods configured |
| UR-02 | Recent MFA Change | +1 | MFA modified in last 30 days |
| UR-03 | Mailbox Delegates | +1 | Others have mailbox access |
| UR-04 | Forwarding Enabled | +3 | Email forwarding active |
| UR-05 | Suspicious Rules | +2 | Redirect/delete inbox rules |
| UR-06 | OAuth Consents | +2 | Third-party app access |
| UR-07 | Admin Role | +2 | Has administrative privileges |
| UR-08 | New Account | +2 | Account < 7 days old |
| UR-09 | Password Reset | +1 | Password reset in last 30 days |
| UR-10 | CA Protection | 0 to +3 | Conditional Access status |

---

## Documentation

Comprehensive documentation is available in the [docs](docs/) folder:

- **[Work Instruction](docs/Work-Instruction-RiskyUserTroubleshooter.md)** - Step-by-step guide for service desk
- **[Indicator Reference](docs/README.md)** - Detailed documentation for all IOCs

---

## Project Structure

```
RiskyUserTroubleshooter/
|-- riskyusertroubleshooter.ps1   # Main script
|-- config/
|   |-- settings.json             # Configuration file
|-- modules/
|   |-- userrisk.ps1              # User risk analysis
|   |-- signinrisk.ps1            # Sign-in risk analysis
|   |-- htmltools.ps1             # HTML utilities
|   |-- htmlbuilder.ps1           # Report builder
|   |-- ioc/                      # IOC detection modules
|       |-- signin/               # Sign-in IOCs (19 modules)
|       |-- userrisk/             # User risk IOCs (10 modules)
|-- api/
|   |-- apikey_abuseipdb.ps1      # AbuseIPDB API key template
|-- docs/                         # Documentation
|   |-- indicators/               # IOC reference docs
|   |-- Work-Instruction-*.md     # User guides
|-- tests/
|   |-- RiskyUserTroubleshooter.Tests.ps1  # Pester tests
|-- reports/                      # Generated HTML reports
|-- logs/                         # Log files
```

---

## Testing

Run the Pester test suite:

```powershell
# Install Pester if needed
Install-Module Pester -Scope CurrentUser -Force

# Run tests
Invoke-Pester ./tests/RiskyUserTroubleshooter.Tests.ps1 -Output Detailed
```

---

## Accessibility

The HTML reports are designed with accessibility in mind:

- ARIA roles and labels for screen readers
- Keyboard navigation (Tab, Arrow keys, Escape)
- Skip link to main content
- Focus management in modals
- No color-only indicators (text labels included)
- High contrast support

---

## License

This project is under a **custom non-commercial license**:

- Free for internal organizational use
- You may adapt and share under attribution
- No commercial use without permission

See [`LICENSE.md`](LICENSE.md) for full terms.

---

## Author

Danny Vorst ([@Virtualite.nl](https://virtualite.nl))

- Website: [virtualite.nl](https://virtualite.nl)
- GitHub: [VirtualiteNL](https://github.com/VirtualiteNL)
