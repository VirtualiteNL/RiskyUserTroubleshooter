# Work Instruction: Risky User Troubleshooter

**Document Type:** Work Instruction
**Audience:** Service Desk / Junior IT Staff
**Last Updated:** 2024

---

## What is Risky User Troubleshooter?

Risky User Troubleshooter is a PowerShell tool that helps you investigate potentially hacked Microsoft 365 user accounts. It creates an easy-to-read HTML report showing:

- **User Risk Score**: Is the account configured securely?
- **Sign-In Risk Score**: Are there suspicious login attempts?
- **Recommended Actions**: What should you do next?

---

## When to Use This Tool

Use this tool when:

- A user reports their account may be compromised
- You see suspicious activity in Microsoft 365
- Identity Protection flagged a risky user
- After a phishing incident affecting a user
- As part of a security incident investigation

---

## Before You Start

### Requirements

1. **PowerShell 7 or newer** must be installed
2. **Permissions**: You need Security Reader or Global Reader role
3. **Modules**: The tool will install required modules automatically

### Check Your Permissions

You need one of these roles in Microsoft 365:
- Security Reader
- Security Administrator
- Global Reader
- Global Administrator

If you don't have permissions, ask your IT Security team.

---

## Step-by-Step Instructions

### Step 1: Open PowerShell

1. Press **Windows + X**
2. Click **Windows Terminal** or **PowerShell**
3. If asked to run as Administrator, click **Yes**

### Step 2: Navigate to the Tool

Type this command and press Enter:

```powershell
cd C:\Path\To\RiskyUserTroubleshooter
```

Replace the path with where the tool is installed.

### Step 3: Run the Tool

Type this command and press Enter:

```powershell
.\riskyusertroubleshooter.ps1
```

### Step 4: Sign In to Microsoft 365

A browser window will open. Sign in with your admin account.

### Step 5: Enter the User's Email

When asked, type the email address of the user you want to investigate:

```
Enter UPN(s) to investigate: john.doe@company.com
```

**Tip:** You can check multiple users by separating emails with commas:
```
Enter UPN(s): john.doe@company.com, jane.smith@company.com
```

### Step 6: Wait for the Report

The tool will:
1. Connect to Microsoft 365
2. Collect user data
3. Analyze sign-in logs
4. Generate the report

This takes about 1-3 minutes.

### Step 7: View the Report

When done, the tool shows where the report is saved:

```
Report saved to: reports/incidentreport-john.doe@company.com.html
```

Open this file in your web browser (Chrome, Edge, Firefox).

---

## Understanding the Report

### Risk Score Summary

At the top of the report, you'll see:

- **User Risk Score**: Security configuration issues
- **Sign-In Risk Score**: Suspicious login activity
- **Breach Probability**: Overall likelihood of compromise

### Color Codes

| Color | Meaning | Action |
|-------|---------|--------|
| 🟢 Green | Low risk | No immediate action |
| 🟡 Yellow | Medium risk | Review and monitor |
| 🟠 Orange | High risk | Investigate soon |
| 🔴 Red | Critical risk | Act immediately |

### User Risk Indicators

These show problems with the account setup:

| Indicator | What It Means |
|-----------|---------------|
| No MFA registered | User has no 2-factor authentication |
| Forwarding enabled | Emails are being sent to another address |
| Suspicious inbox rules | Rules that may hide hacker activity |
| No CA protection | User not protected by security policies |

### Sign-In Risk Indicators

These show suspicious login attempts:

| Indicator | What It Means |
|-----------|---------------|
| MFA failure | Someone knew the password but failed MFA |
| Impossible travel | Logins from far locations in short time |
| Foreign IP | Login from unexpected country |
| Session anomaly | Something changed during the login session |

### Clicking for Details

Click on any row in the tables to see more information in a popup.

---

## What To Do Based on Results

### Low Risk (Green)

1. No immediate action required
2. Document your investigation
3. Close the ticket

### Medium Risk (Yellow)

1. Review the specific indicators
2. Ask the user if activity looks normal
3. Check if any flagged items are expected
4. Document findings
5. Consider password reset if unsure

### High Risk (Orange)

1. Contact IT Security team
2. Consider disabling the account temporarily
3. Reset the user's password
4. Revoke all active sessions
5. Check for data access/theft
6. Document everything

### Critical Risk (Red)

1. **Immediately escalate to IT Security**
2. Disable the account
3. Reset password
4. Revoke all sessions
5. Check audit logs for what was accessed
6. This is a security incident - follow incident procedure

---

## Common Tasks After Investigation

### Reset User's Password

```powershell
# In Azure AD admin center, or:
Set-AzureADUserPassword -ObjectId "user@company.com" -ForceChangePasswordNextLogin $true
```

### Revoke All Sessions

```powershell
# In Azure AD admin center, find user and click "Revoke sessions"
# Or:
Revoke-AzureADUserAllRefreshToken -ObjectId "user@company.com"
```

### Remove Forwarding Rules

1. Go to Exchange Admin Center
2. Find the user's mailbox
3. Check Mail Flow > Forwarding
4. Remove any suspicious forwards

### Check Inbox Rules

1. Go to Exchange Admin Center
2. Find the user's mailbox
3. Go to Mail Flow > Inbox rules
4. Review and delete suspicious rules

---

## Troubleshooting

### "Access Denied" Error

You don't have the required permissions. Ask your admin to give you Security Reader role.

### "Module not found" Error

The tool will try to install modules automatically. If it fails:

```powershell
Install-Module Microsoft.Graph -Scope CurrentUser
Install-Module ExchangeOnlineManagement -Scope CurrentUser
```

### "User not found" Error

Check that you typed the email address correctly. The user must exist in your Microsoft 365 tenant.

### Tool Runs Very Slowly

This is normal for users with many sign-ins. The tool analyzes 30 days of data.

---

## Getting Help

If you need help:

1. Check this documentation first
2. Ask your IT Security team
3. Check the GitHub page for known issues

---

## Glossary

| Term | Simple Explanation |
|------|-------------------|
| MFA | Multi-Factor Authentication - extra security step when logging in |
| UPN | User Principal Name - the user's email address for login |
| CA | Conditional Access - security rules that control who can access what |
| IOC | Indicator of Compromise - sign that something may be wrong |
| AbuseIPDB | Database of known bad IP addresses |
| Session | One continuous period of being logged in |

---

## Quick Reference Card

```
┌─────────────────────────────────────────────────┐
│         RISKY USER TROUBLESHOOTER               │
├─────────────────────────────────────────────────┤
│ 1. Open PowerShell                              │
│ 2. cd to tool folder                            │
│ 3. Run: .\riskyusertroubleshooter.ps1          │
│ 4. Sign in when prompted                        │
│ 5. Enter user email                             │
│ 6. Wait for report                              │
│ 7. Open HTML report in browser                  │
├─────────────────────────────────────────────────┤
│ GREEN  = OK          ORANGE = Investigate       │
│ YELLOW = Review      RED    = Escalate Now      │
└─────────────────────────────────────────────────┘
```
