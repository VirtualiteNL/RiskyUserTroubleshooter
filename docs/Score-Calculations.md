# Score Calculations

This document explains how risk scores are calculated in the Risky User Troubleshooter.

---

## Overview

The tool calculates three types of scores:

1. **User Risk Score** - Based on account configuration issues
2. **Sign-In Risk Score** - Based on suspicious sign-in activity (per sign-in)
3. **Breach Probability** - Overall likelihood of account compromise

---

## User Risk Score Calculation

### Formula

```
User Risk Score = Sum of all triggered UR indicator points
```

### Indicator Points (UR-01 to UR-10)

| ID | Indicator | Points | Condition |
|----|-----------|--------|-----------|
| UR-01 | No MFA Registered | +3 | `$activeMfa.Count -eq 0` |
| UR-02 | Recent MFA Change | +1 | MFA audit events in last 30 days |
| UR-03 | Mailbox Delegates | +1 | `$delegates.Count -gt 0` |
| UR-04 | Forwarding Enabled | +3 | Mailbox forwarding OR ForwardTo rules |
| UR-05 | Suspicious Inbox Rules | +2 | Rules with RedirectTo or DeleteMessage |
| UR-06 | OAuth Consents | +2 | `$oauthApps.Count -gt 0` |
| UR-07 | Active Admin Role | +2 | `$directoryRoles.Count -gt 0` |
| UR-08 | New Account | +2 | Account age < 7 days |
| UR-09 | Password Reset | +1 | Password reset in last 30 days |
| UR-10 | CA Protection | 0-3 | See CA Protection scoring below |

### CA Protection Scoring (UR-10)

| Status | Points | Condition |
|--------|--------|-----------|
| Full protection | 0 | User covered by MFA policy for all apps |
| Partial protection | +2 | MFA policy but not all apps covered |
| Block policy only | +1 | No MFA policy, but has block policy |
| No protection | +3 | Not covered by any CA policy |

### Maximum User Risk Score

```
Maximum = 3 + 1 + 1 + 3 + 2 + 2 + 2 + 2 + 1 + 3 = 20 points
```

### Code Reference

```powershell
# modules/userrisk.ps1 (lines 182-195)
$riskIndicators = @(
    @{ Name = "No MFA registered";          Condition = ($activeMfa.Count -eq 0); Points = 3 },
    @{ Name = "Recent MFA change";          Condition = ($recentMfaChanges.Count -gt 0); Points = 1 },
    @{ Name = "Mailbox shared with others"; Condition = ($delegates.Count -gt 0); Points = 1 },
    @{ Name = "Forwarding enabled";         Condition = $hasForwarding; Points = 3 },
    @{ Name = "Suspicious inbox rules";     Condition = ($otherSuspiciousRules.Count -gt 0); Points = 2 },
    @{ Name = "OAuth consents";             Condition = ($oauthApps.Count -gt 0); Points = 2 },
    @{ Name = "Active admin role";          Condition = ($directoryRoles.Count -gt 0); Points = 2 },
    @{ Name = "Account < 7 days old";       Condition = $isNewAccount; Points = 2 },
    @{ Name = "Password reset < 30 days";   Condition = ($pwdEvents.Count -gt 0); Points = 1 }
)
# CA Protection indicator added separately from ioc-userrisk-ca.ps1
```

---

## Sign-In Risk Score Calculation

### Formula

```
Sign-In Score = Sum of all triggered SR indicator points (including negative)
Minimum Score = 0 (negative totals are capped at 0)
```

### Indicator Points (SR-01 to SR-19)

#### Risk Indicators (Positive Points)

| ID | Indicator | Points | Condition |
|----|-----------|--------|-----------|
| SR-01 | Legacy Protocol | +3 | `ClientAppUsed -match 'imap\|pop\|smtp\|other\|unknown'` |
| SR-02 | MFA Failure | +3 | ErrorCode in MFA failure codes |
| SR-03 | No MFA Used | +2 | `AuthenticationDetails.Count -eq 0` |
| SR-04 | CA Policy Failure | +2 | `ConditionalAccessStatus -in @('failure','unknownFutureValue')` |
| SR-05 | Foreign IP | +1 to +3 | Non-NL location, scaled by AbuseIPDB score |
| SR-06 | Suspicious IP+ASN | +3 | AbuseScore >= 70 AND untrusted ASN |
| SR-07 | Impossible Travel | +4 | Speed > 1000 km/h between sign-ins |
| SR-08 | Outside Hours | +1 | Hour outside working hours ± 2h buffer |
| SR-09 | Session Anomaly | +4 | IP/device/country changed in session |
| SR-10 | Country Switch | +2 | Country changed during session |
| SR-11 | Multiple IPs | +1 | Multiple IPs in same session |
| SR-12 | Device Change | +1 | Browser/OS changed during session |
| SR-16 | Microsoft Risk | +1 to +4 | Based on RiskLevelDuringSignIn |

#### Safety Indicators (Negative Points)

| ID | Indicator | Points | Condition |
|----|-----------|--------|-----------|
| SR-13 | Trusted Device | **-2** | `DeviceDetail.TrustType -eq "Azure AD joined"` |
| SR-14 | Compliant Device | **-3** | `DeviceDetail.IsCompliant -eq $true` |
| SR-15 | Location Netherlands | **-1** | `Location.CountryOrRegion -in @("NL", "Netherlands")` |
| SR-17 | Trusted Location IP | **-2** | IP in CA Named Location (trusted) |
| SR-18 | Frequent IP (MFA) | **-1** | IP used 3+ times with MFA success |
| SR-19 | Frequent IP (Compliant) | **-2** | IP used 3+ times with compliant device |

### SR-05 Foreign IP Scoring

| AbuseIPDB Score | Points |
|-----------------|--------|
| 0-9 | +1 |
| 10-25 | +1 |
| 26-49 | +2 |
| 50+ | +3 |

### SR-16 Microsoft Risk Scoring

| Microsoft Risk Level | Points |
|---------------------|--------|
| High | +4 |
| Medium | +2 |
| Low | +1 |
| None/Hidden | 0 |

### Maximum Sign-In Risk Score

```
Maximum Positive = 3 + 3 + 2 + 2 + 3 + 3 + 4 + 1 + 4 + 2 + 1 + 1 + 4 = 33 points
Maximum Negative = -2 + -3 + -1 + -2 + -1 + -2 = -11 points

Theoretical Range: -11 to +33
Practical Range: 0 to +33 (minimum capped at 0)
```

### Code Reference

```powershell
# modules/signinrisk.ps1 (lines 225-240)
$score = ($breakdown | Where-Object { $_.Points -ne 0 } |
          Measure-Object -Property Points -Sum).Sum

# Enforce minimum score of 0
if ($score -lt 0) { $score = 0 }
```

### Mutual Exclusion Rules

Only ONE of SR-02, SR-03, or SR-04 is applied per sign-in:

```powershell
# Priority order:
# 1. SR-02 (MFA Failure) - highest priority
# 2. SR-04 (CA Policy Failure) - if SR-02 not triggered
# 3. SR-03 (No MFA Used) - if neither SR-02 nor SR-04 triggered
```

---

## Risk Level Classification

### User Risk Levels

| Score | Level | CSS Class |
|-------|-------|-----------|
| 10+ | Critical | `status-critical` |
| 7-9 | High | `status-bad` |
| 4-6 | Medium | `status-warning` |
| 0-3 | Low | `status-good` |

### Sign-In Risk Levels

| Score | Level | CSS Class |
|-------|-------|-----------|
| 10+ | Critical | `risk-critical` |
| 7-9 | High | `risk-high` |
| 4-6 | Medium | `risk-medium` |
| 1-3 | Low | `risk-low` |
| 0 | None | - |

### Code Reference

```powershell
# modules/userrisk.ps1 (lines 237-242)
switch ($true) {
    { $RiskScore -ge 10 } { $RiskLevel = "Critical"; break }
    { $RiskScore -ge 7 }  { $RiskLevel = "High"; break }
    { $RiskScore -ge 4 }  { $RiskLevel = "Medium"; break }
    default               { $RiskLevel = "Low"; break }
}
```

---

## Breach Probability Calculation

The breach probability is calculated in `modules/htmltools.ps1` using a weighted category system.

### Category Weights

| Category | Max Score | Weight |
|----------|-----------|--------|
| Credential Compromise | 40 | 40% |
| Session Anomalies | 35 | 35% |
| Config Weakness | 20 | 20% |
| Temporal | 5 | 5% |

### Category Scoring

#### Credential Compromise (max 40 points)

| Trigger | Points |
|---------|--------|
| MFA failures | +10 per failure (max 20) |
| Recent MFA modification | +10 |
| Recent password reset | +8 |

#### Session Anomalies (max 35 points)

| Trigger | Points |
|---------|--------|
| Impossible travel | +8 per detection (max 15) |
| Session anomalies | +5 per anomaly (max 15) |
| Country switches | +3 per switch (max 10) |

#### Config Weakness (max 20 points)

| Trigger | Points |
|---------|--------|
| No MFA registered | +8 |
| Email forwarding enabled | +8 |
| Suspicious inbox rules | +4 |
| No CA protection | +6 |
| Legacy protocol usage | +4 |

#### Temporal (max 5 points)

| Trigger | Points |
|---------|--------|
| High activity concentration | +5 |

### Multipliers

After calculating base percentage, multipliers are applied:

| Condition | Multiplier |
|-----------|------------|
| Credential indicator present | 1.3x |
| Admin account | 1.2x |
| 3+ categories affected | 1.15x |

### Final Calculation

```powershell
$totalScore = Sum of all category scores (capped at max)
$basePercentage = $totalScore
$finalPercentage = Min(100, Round($basePercentage * $multiplier))
```

### Probability Status

| Percentage | Status | Color |
|------------|--------|-------|
| 71-100% | High Likelihood | #8b0000 (dark red) |
| 41-70% | Probable | #dc3545 (red) |
| 21-40% | Possible | #f0ad4e (orange) |
| 0-20% | Unlikely | #2cc29f (green) |

### Code Reference

```powershell
# modules/htmltools.ps1 - Get-BreachProbability function (lines 1-197)
```

---

## Display Threshold

Sign-ins are only displayed in the report if:

```powershell
# Sign-in must have score > 1 to be included in riskySignIns
if ($score -gt 1) {
    $riskySignIns += $s
}

# Sign-in must have score >= 1 for detailed display
$filteredSignIns = $riskySignIns | Where-Object { $_.SignInScore -ge 1 }
```

---

## Configuration

All thresholds are configurable in `config/settings.json`:

```json
{
    "riskThresholds": {
        "critical": 10,
        "high": 7,
        "medium": 4,
        "low": 1
    },
    "breachProbability": {
        "weights": {
            "credentialCompromise": 40,
            "sessionAnomalies": 35,
            "configWeakness": 20,
            "temporal": 5
        },
        "thresholds": {
            "low": 20,
            "medium": 40,
            "high": 70,
            "critical": 100
        },
        "multipliers": {
            "credentialIndicator": 1.5,
            "adminAccount": 1.3,
            "multipleCategories": 1.2
        }
    }
}
```

---

## Example Calculations

### Example 1: Low Risk User

```
User Indicators:
- No issues detected

User Risk Score: 0 (Low)

Sign-In:
- Location: Netherlands (-1)
- Compliant device (-3)
- MFA used (0)

Sign-In Score: -4 → capped to 0 (None)
```

### Example 2: Medium Risk User

```
User Indicators:
- Recent MFA change (+1)
- Mailbox delegates (+1)
- Partial CA coverage (+2)

User Risk Score: 4 (Medium)

Sign-In:
- Foreign IP with abuse score 30 (+2)
- Outside working hours (+1)

Sign-In Score: 3 (Low)
```

### Example 3: Critical Risk User

```
User Indicators:
- No MFA registered (+3)
- Forwarding enabled (+3)
- No CA protection (+3)
- Active admin role (+2)

User Risk Score: 11 (Critical)

Sign-In:
- MFA failure (+3)
- Impossible travel (+4)
- Foreign IP abuse score 80 (+3)
- Suspicious IP+ASN (+3)

Sign-In Score: 13 (Critical)

Breach Probability:
- MFA failures: +20
- No MFA registered: +8
- Forwarding enabled: +8
- Impossible travel: +8
- Admin account multiplier: 1.2x
- Multiple categories: 1.15x

Base: 44 × 1.2 × 1.15 = 60.7%
Status: Probable
```
