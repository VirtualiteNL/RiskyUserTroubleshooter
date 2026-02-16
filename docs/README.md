# RiskyUserTroubleshooter Documentation

## Overview

This folder contains comprehensive documentation for the RiskyUserTroubleshooter tool.

## Contents

### Work Instruction

- **[Work-Instruction-RiskyUserTroubleshooter.md](Work-Instruction-RiskyUserTroubleshooter.md)** - Step-by-step guide for service desk staff

### Indicator Reference

#### Sign-In Risk Indicators (SR-01 to SR-19)

| ID | Name | Points | Documentation |
|----|------|--------|---------------|
| SR-01 | Legacy Protocol | +3 | [View](indicators/signin/SR-01-Legacy-Protocol.md) |
| SR-02 | MFA Failure | +3 | [View](indicators/signin/SR-02-MFA-Failure.md) |
| SR-03 | No MFA Used | +2 | [View](indicators/signin/SR-03-No-MFA-Used.md) |
| SR-04 | CA Policy Failure | +2 | [View](indicators/signin/SR-04-CA-Policy-Failure.md) |
| SR-05 | Foreign IP | +1 to +3 | [View](indicators/signin/SR-05-Foreign-IP.md) |
| SR-06 | Suspicious IP+ASN | +3 | [View](indicators/signin/SR-06-Suspicious-IP-ASN.md) |
| SR-07 | Impossible Travel | +4 | [View](indicators/signin/SR-07-Impossible-Travel.md) |
| SR-08 | Login Outside Hours | +1 | [View](indicators/signin/SR-08-Login-Outside-Hours.md) |
| SR-09 | Session Anomaly | +4 | [View](indicators/signin/SR-09-Session-Anomaly.md) |
| SR-10 | Country Switch | +2 | [View](indicators/signin/SR-10-Country-Switch.md) |
| SR-11 | Multiple IPs | +1 | [View](indicators/signin/SR-11-Multiple-IPs.md) |
| SR-12 | Device Change | +1 | [View](indicators/signin/SR-12-Device-Change.md) |
| SR-13 | Trusted Device | **-2** | [View](indicators/signin/SR-13-Trusted-Device.md) |
| SR-14 | Compliant Device | **-3** | [View](indicators/signin/SR-14-Compliant-Device.md) |
| SR-15 | Location Netherlands | **-1** | [View](indicators/signin/SR-15-Location-Netherlands.md) |
| SR-16 | Microsoft Risk Detection | +2 to +4 | [View](indicators/signin/SR-16-Microsoft-Risk-Detection.md) |
| SR-17 | Trusted Location IP | **-2** | [View](indicators/signin/SR-17-Trusted-Location-IP.md) |
| SR-18 | Frequently Used IP (MFA) | **-1** | [View](indicators/signin/SR-18-Frequently-Used-IP-MFA.md) |
| SR-19 | Frequently Used IP (Compliant) | **-2** | [View](indicators/signin/SR-19-Frequently-Used-IP-Compliant.md) |

#### User Risk Indicators (UR-01 to UR-10)

| ID | Name | Points | Documentation |
|----|------|--------|---------------|
| UR-01 | No MFA Registered | +3 | [View](indicators/userrisk/UR-01-No-MFA-Registered.md) |
| UR-02 | Recent MFA Change | +1 | [View](indicators/userrisk/UR-02-Recent-MFA-Change.md) |
| UR-03 | Mailbox Delegates | +1 | [View](indicators/userrisk/UR-03-Mailbox-Delegates.md) |
| UR-04 | Forwarding Enabled | +3 | [View](indicators/userrisk/UR-04-Forwarding-Enabled.md) |
| UR-05 | Suspicious Inbox Rules | +2 | [View](indicators/userrisk/UR-05-Suspicious-Inbox-Rules.md) |
| UR-06 | OAuth Consents | +2 | [View](indicators/userrisk/UR-06-OAuth-Consents.md) |
| UR-07 | Active Admin Role | +2 | [View](indicators/userrisk/UR-07-Active-Admin-Role.md) |
| UR-08 | New Account | +2 | [View](indicators/userrisk/UR-08-New-Account.md) |
| UR-09 | Password Reset | +1 | [View](indicators/userrisk/UR-09-Password-Reset.md) |
| UR-10 | CA Protection | 0 to +3 | [View](indicators/userrisk/UR-10-CA-Protection.md) |

## Understanding Risk Scores

### Positive Points (Risk Indicators)

Positive points indicate potential security issues:
- **+1**: Low severity, monitor situation
- **+2**: Medium severity, investigate
- **+3**: High severity, take action
- **+4**: Critical severity, immediate response

### Negative Points (Safety Indicators)

Negative points indicate secure conditions that reduce the overall score:
- **-1**: Minor positive signal
- **-2**: Moderate positive signal
- **-3**: Strong positive signal

### Risk Level Thresholds

| Score | Risk Level | Recommended Action |
|-------|------------|-------------------|
| 0-3 | Low | Document and close |
| 4-6 | Medium | Review and verify |
| 7-9 | High | Investigate thoroughly |
| 10+ | Critical | Immediate response required |

## Updates

### Recent Changes (2024)

1. **New Indicators Added**:
   - SR-17: Trusted Location IP
   - SR-18: Frequently Used IP (MFA verified)
   - SR-19: Frequently Used IP (Compliant device)

2. **Block Policy Detection**:
   - UR-10 now detects block policies as alternative protection
   - Shows "Block policy only: [name]" when applicable

3. **Audit Log Optimization**:
   - Repetitive audit entries (10+) are now grouped for performance
