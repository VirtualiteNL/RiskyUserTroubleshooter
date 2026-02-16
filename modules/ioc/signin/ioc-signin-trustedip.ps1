<#
.SYNOPSIS
    Microsoft 365 Risky User Troubleshooter

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

# Global cache for trusted IP data (populated once per session)
$script:TrustedIpCache = $null

function Get-TrustedIpProfile {
    <#
    .SYNOPSIS
        Builds a trusted IP profile from CA Named Locations and historical sign-in patterns.
    .DESCRIPTION
        Retrieves CA Named Locations marked as trusted and analyzes sign-in history
        to identify frequently used IPs with successful MFA or compliant devices.
    .PARAMETER SignIns
        Array of sign-in objects to analyze for IP patterns.
    #>
    param (
        [Parameter(Mandatory)]
        [array]$SignIns
    )

    # Return cached data if available
    if ($null -ne $script:TrustedIpCache) {
        Write-Log -Type "Information" -Message "Using cached trusted IP profile"
        return $script:TrustedIpCache
    }

    Write-Log -Type "Information" -Message "Building trusted IP profile..."
    Write-Host "Building trusted IP profile..." -ForegroundColor Gray

    $trustedIpRanges = @()
    $ipStats = @{}

    # Get CA Named Locations (trusted)
    try {
        $namedLocations = Get-MgIdentityConditionalAccessNamedLocation -All -ErrorAction SilentlyContinue
        if ($namedLocations) {
            $trustedLocations = $namedLocations | Where-Object { $_.AdditionalProperties.isTrusted -eq $true }

            foreach ($location in $trustedLocations) {
                # Handle IP-based named locations
                if ($location.AdditionalProperties.'@odata.type' -eq '#microsoft.graph.ipNamedLocation') {
                    $ipRanges = $location.AdditionalProperties.ipRanges
                    if ($ipRanges) {
                        foreach ($range in $ipRanges) {
                            $trustedIpRanges += @{
                                CidrAddress = $range.cidrAddress
                                LocationName = $location.DisplayName
                            }
                        }
                    }
                }
            }
            Write-Log -Type "Information" -Message "Found $($trustedIpRanges.Count) trusted IP ranges from $($trustedLocations.Count) Named Locations"
        }
    }
    catch {
        Write-Log -Type "Alert" -Message "Could not retrieve CA Named Locations: $($_.Exception.Message)"
    }

    # Analyze historical sign-ins for IP patterns
    if ($SignIns -and $SignIns.Count -gt 0) {
        $ipGroups = $SignIns | Where-Object { $_.IpAddress } | Group-Object IpAddress

        foreach ($group in $ipGroups) {
            $ip = $group.Name
            $signInsFromIp = $group.Group

            # Count MFA successes - check for actual MFA requirement or multiple auth factors
            # AuthenticationRequirement = 'multiFactorAuthentication' indicates MFA was required
            # Or check if AuthenticationDetails contains multiple successful factors
            $mfaSuccessCount = @($signInsFromIp | Where-Object {
                # Method 1: Check AuthenticationRequirement property
                $_.AuthenticationRequirement -eq 'multiFactorAuthentication' -or
                # Method 2: Check if multiple authentication methods were used successfully
                ($_.AuthenticationDetails | Where-Object { $_.Succeeded -eq $true }).Count -ge 2 -or
                # Method 3: Check AuthenticationMethodsUsed for MFA indicators
                ($_.AuthenticationMethodsUsed -and $_.AuthenticationMethodsUsed.Count -ge 2)
            }).Count

            # Count compliant device sign-ins
            $compliantCount = @($signInsFromIp | Where-Object {
                $_.DeviceDetail.IsCompliant -eq $true
            }).Count

            # Count Azure AD joined device sign-ins (alternative trust indicator)
            $trustedDeviceCount = @($signInsFromIp | Where-Object {
                $_.DeviceDetail.TrustType -in @('AzureAd', 'Hybrid', 'ServerAd')
            }).Count

            $ipStats[$ip] = @{
                IP = $ip
                TotalCount = $group.Count
                MfaSuccessCount = $mfaSuccessCount
                CompliantCount = $compliantCount
                TrustedDeviceCount = $trustedDeviceCount
            }
        }

        # Log summary of IP statistics for debugging
        $ipsWithMfa = @($ipStats.Values | Where-Object { $_.MfaSuccessCount -gt 0 }).Count
        $ipsWithCompliant = @($ipStats.Values | Where-Object { $_.CompliantCount -gt 0 }).Count
        Write-Log -Type "Information" -Message "Analyzed $($ipStats.Count) unique IPs: $ipsWithMfa with MFA, $ipsWithCompliant with compliant devices"
    }

    # Build and cache the profile
    $script:TrustedIpCache = @{
        TrustedIpRanges = $trustedIpRanges
        IpStats = $ipStats
    }

    return $script:TrustedIpCache
}

function Test-IpInTrustedLocation {
    <#
    .SYNOPSIS
        Checks if an IP address falls within any trusted CA Named Location range.
    .PARAMETER IpAddress
        The IP address to check.
    .PARAMETER TrustedRanges
        Array of trusted IP ranges from CA Named Locations (can be empty).
    #>
    param (
        [Parameter(Mandatory)]
        [string]$IpAddress,

        [Parameter(Mandatory = $false)]
        [array]$TrustedRanges = @()
    )

    if (-not $TrustedRanges -or $TrustedRanges.Count -eq 0) {
        return @{ IsTrusted = $false; LocationName = $null }
    }

    foreach ($range in $TrustedRanges) {
        $cidr = $range.CidrAddress
        if (-not $cidr) { continue }

        try {
            # Parse CIDR notation (e.g., "192.168.1.0/24" or "2001:db8::/32")
            $parts = $cidr -split '/'
            $networkAddress = $parts[0]
            $prefixLength = [int]$parts[1]

            # Check if it's IPv4 or IPv6
            $isIPv6 = $networkAddress -match ':'
            $inputIsIPv6 = $IpAddress -match ':'

            # Skip if IP version doesn't match
            if ($isIPv6 -ne $inputIsIPv6) { continue }

            if (-not $isIPv6) {
                # IPv4 CIDR check
                $networkBytes = [System.Net.IPAddress]::Parse($networkAddress).GetAddressBytes()
                $ipBytes = [System.Net.IPAddress]::Parse($IpAddress).GetAddressBytes()

                # Convert to 32-bit integers for comparison
                [Array]::Reverse($networkBytes)
                [Array]::Reverse($ipBytes)
                $networkInt = [BitConverter]::ToUInt32($networkBytes, 0)
                $ipInt = [BitConverter]::ToUInt32($ipBytes, 0)

                # Create subnet mask
                $mask = [uint32]::MaxValue -shl (32 - $prefixLength)

                if (($networkInt -band $mask) -eq ($ipInt -band $mask)) {
                    return @{ IsTrusted = $true; LocationName = $range.LocationName }
                }
            }
            else {
                # IPv6 CIDR check (simplified - check prefix bytes)
                $networkAddr = [System.Net.IPAddress]::Parse($networkAddress)
                $ipAddr = [System.Net.IPAddress]::Parse($IpAddress)
                $networkBytes = $networkAddr.GetAddressBytes()
                $ipBytes = $ipAddr.GetAddressBytes()

                # Compare the first prefixLength bits
                $fullBytes = [math]::Floor($prefixLength / 8)
                $remainingBits = $prefixLength % 8

                $match = $true
                for ($i = 0; $i -lt $fullBytes; $i++) {
                    if ($networkBytes[$i] -ne $ipBytes[$i]) {
                        $match = $false
                        break
                    }
                }

                if ($match -and $remainingBits -gt 0) {
                    $mask = 0xFF -shl (8 - $remainingBits)
                    if (($networkBytes[$fullBytes] -band $mask) -ne ($ipBytes[$fullBytes] -band $mask)) {
                        $match = $false
                    }
                }

                if ($match) {
                    return @{ IsTrusted = $true; LocationName = $range.LocationName }
                }
            }
        }
        catch {
            # Skip invalid CIDR entries
            Write-Log -Type "Alert" -Message "Invalid CIDR format: $cidr - $($_.Exception.Message)"
            continue
        }
    }

    return @{ IsTrusted = $false; LocationName = $null }
}

function Test-SignInTrustedIpIOCs {
    <#
    .SYNOPSIS
        Evaluates trusted IP IOCs (SR-17, SR-18, SR-19) for a sign-in.
    .DESCRIPTION
        Checks if the sign-in IP is from a trusted location or frequently used
        with MFA/compliant devices. Returns negative scores for trusted indicators.
        Points are synchronized with config/settings.json iocDefinitions.signInRisk
    .PARAMETER SignIn
        The sign-in object to evaluate.
    .PARAMETER TrustedProfile
        The trusted IP profile from Get-TrustedIpProfile.
    #>
    param (
        [Parameter(Mandatory)]
        $SignIn,

        [Parameter(Mandatory)]
        [hashtable]$TrustedProfile
    )

    $results = @()
    $ip = $SignIn.IpAddress

    if (-not $ip) {
        return $results
    }

    try {
        # SR-17: Trusted Location IP (-2 points)
        # IP is in a CA Named Location marked as "trusted"
        $trustedCheck = Test-IpInTrustedLocation -IpAddress $ip -TrustedRanges $TrustedProfile.TrustedIpRanges
        if ($trustedCheck.IsTrusted) {
            $results += @{
                Name = "Trusted Location IP ($($trustedCheck.LocationName))"
                Points = -2
            }
            Write-Log -Type "Information" -Message "SR-17: IP $ip is in trusted location '$($trustedCheck.LocationName)'"
        }
    }
    catch {
        Write-Log -Type "Error" -Message "Failed to evaluate SR-17 for ${ip}: $($_.Exception.Message)"
    }

    try {
        # Get IP stats from profile
        $ipStat = $TrustedProfile.IpStats[$ip]

        if ($ipStat) {
            # Debug: Log IP statistics for troubleshooting
            Write-Log -Type "Debug" -Message "IP Stats for ${ip}: Total=$($ipStat.TotalCount), MFA=$($ipStat.MfaSuccessCount), Compliant=$($ipStat.CompliantCount)"

            # SR-18: Frequently Used IP with MFA Success (-1 point)
            # IP used 3+ times in last 30 days with successful MFA
            if ($ipStat.MfaSuccessCount -ge 3) {
                $results += @{
                    Name = "Frequently Used IP (MFA verified $($ipStat.MfaSuccessCount)x)"
                    Points = -1
                }
                Write-Log -Type "Information" -Message "SR-18: IP $ip used $($ipStat.MfaSuccessCount)x with MFA success"
            }

            # SR-19: Frequently Used IP with Compliant Device (-2 points)
            # IP used 3+ times in last 30 days with compliant device
            if ($ipStat.CompliantCount -ge 3) {
                $results += @{
                    Name = "Frequently Used IP (Compliant device $($ipStat.CompliantCount)x)"
                    Points = -2
                }
                Write-Log -Type "Information" -Message "SR-19: IP $ip used $($ipStat.CompliantCount)x with compliant device"
            }
        }
        else {
            Write-Log -Type "Debug" -Message "No IP stats found for ${ip}"
        }
    }
    catch {
        Write-Log -Type "Error" -Message "Failed to evaluate SR-18/SR-19 for ${ip}: $($_.Exception.Message)"
    }

    return $results
}

function Clear-TrustedIpCache {
    <#
    .SYNOPSIS
        Clears the trusted IP cache to force refresh on next call.
    #>
    $script:TrustedIpCache = $null
    Write-Log -Type "Information" -Message "Trusted IP cache cleared"
}
