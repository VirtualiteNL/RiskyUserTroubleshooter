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
function Get-UserMfaMethods {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)][string]$UserId
    )

    $methods = @()

    Write-Host "🔐 Retrieving MFA methods for user: $UserId" -ForegroundColor Cyan

    try {
        # 📱 Phone/SMS or voice call MFA
        $phones = Get-MgUserAuthenticationPhoneMethod -UserId $UserId -ErrorAction SilentlyContinue
        foreach ($p in $phones) {
            $methods += [PSCustomObject]@{
                Type         = 'Phone (SMS/Call)'
                Details      = $p.PhoneNumber
                RegisteredOn = $p.CreatedDateTime ?? 'Unknown'
            }
        }

        # 📲 Microsoft Authenticator app
        $apps = Get-MgUserAuthenticationMicrosoftAuthenticatorMethod -UserId $UserId -ErrorAction SilentlyContinue
        foreach ($a in $apps) {
            $methods += [PSCustomObject]@{
                Type         = 'Authenticator app'
                Details      = $a.DeviceTag ?? 'Unknown device'
                RegisteredOn = $a.CreatedDateTime ?? 'Unknown'
            }
        }

        # 🗝️ FIDO2 security keys
        $fido = Get-MgUserAuthenticationFido2Method -UserId $UserId -ErrorAction SilentlyContinue
        foreach ($f in $fido) {
            $methods += [PSCustomObject]@{
                Type         = 'FIDO2 key'
                Details      = $f.Model ?? 'Unknown'
                RegisteredOn = $f.CreatedDateTime ?? 'Unknown'
            }
        }

        # 👁️ Windows Hello for Business
        $hello = Get-MgUserAuthenticationWindowsHelloForBusinessMethod -UserId $UserId -ErrorAction SilentlyContinue
        foreach ($h in $hello) {
            $methods += [PSCustomObject]@{
                Type         = 'Windows Hello for Business'
                Details      = $h.DisplayName ?? 'Unknown device'
                RegisteredOn = $h.CreatedDateTime ?? 'Unknown'
            }
        }

        if ($methods.Count) {
            Write-Host "✅ Found $($methods.Count) MFA method(s) for $UserId" -ForegroundColor Green
            Write-Log -Type "Information" -Message "Found $($methods.Count) MFA method(s) for user $UserId"
        } else {
            Write-Host "⚠️ No MFA methods registered for $UserId" -ForegroundColor Yellow
            Write-Log -Type "Warning" -Message "No MFA methods registered for user $UserId"
        }
    }
    catch {
        Write-Host "❌ Failed to enumerate MFA methods for $UserId" -ForegroundColor Red
        Write-Log -Type "Error" -Message "Failed to enumerate MFA methods for user ${UserId}: $_"
    }

    return $methods
}
