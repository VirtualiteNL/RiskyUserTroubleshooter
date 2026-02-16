<#
.SYNOPSIS
    Pester tests for RiskyUserTroubleshooter

.DESCRIPTION
    Unit tests for core functions in the RiskyUserTroubleshooter tool.
    Run with: Invoke-Pester ./tests/RiskyUserTroubleshooter.Tests.ps1

.AUTHOR
    Danny Vorst (@Virtualite.nl)
#>

BeforeAll {
    # Load modules
    $modulePath = Join-Path $PSScriptRoot "..\modules"
    . "$modulePath\logger.ps1"
    . "$modulePath\config.ps1"
    . "$modulePath\htmltools.ps1"
}

Describe "Logger Module" {
    BeforeEach {
        $testLogPath = Join-Path $TestDrive "test.log"
        $Global:LogFilePath = ""
        $Global:LogLevel = "Information"
        $Global:EnableDebugLogging = $false
        $Global:EnableJsonLogging = $false
    }

    Context "Start-Log" {
        It "Should create a new log file" {
            Start-Log -Path $testLogPath
            Test-Path $testLogPath | Should -Be $true
        }

        It "Should set the global log file path" {
            Start-Log -Path $testLogPath
            $Global:LogFilePath | Should -Be $testLogPath
        }

        It "Should replace existing log file by default" {
            "Existing content" | Out-File $testLogPath
            Start-Log -Path $testLogPath
            $content = Get-Content $testLogPath -Raw
            $content | Should -Not -Match "Existing content"
        }

        It "Should append to existing log file when -Append is specified" {
            "Existing content" | Out-File $testLogPath
            Start-Log -Path $testLogPath -Append
            $content = Get-Content $testLogPath -Raw
            $content | Should -Match "Existing content"
        }
    }

    Context "Write-Log" {
        BeforeEach {
            Start-Log -Path $testLogPath
        }

        It "Should write log entries with correct format" {
            Write-Log -Type "Information" -Message "Test message"
            $content = Get-Content $testLogPath -Raw
            $content | Should -Match "Test message"
            $content | Should -Match "\[INFORMATION\]"
        }

        It "Should skip debug messages when debug logging is disabled" {
            Write-Log -Type "Debug" -Message "Debug message"
            $content = Get-Content $testLogPath -Raw
            $content | Should -Not -Match "Debug message"
        }

        It "Should include debug messages when debug logging is enabled" {
            $Global:EnableDebugLogging = $true
            $Global:LogLevel = "Debug"
            Write-Log -Type "Debug" -Message "Debug message"
            $content = Get-Content $testLogPath -Raw
            $content | Should -Match "Debug message"
        }

        It "Should respect log level filtering" {
            $Global:LogLevel = "Alert"
            Write-Log -Type "Information" -Message "Info message"
            Write-Log -Type "Alert" -Message "Alert message"
            $content = Get-Content $testLogPath -Raw
            $content | Should -Not -Match "Info message"
            $content | Should -Match "Alert message"
        }
    }

    Context "Set-LogConfiguration" {
        It "Should set log level correctly" {
            Set-LogConfiguration -Level "Alert"
            $Global:LogLevel | Should -Be "Alert"
        }

        It "Should enable debug logging when specified" {
            Set-LogConfiguration -EnableDebug
            $Global:EnableDebugLogging | Should -Be $true
            $Global:LogLevel | Should -Be "Debug"
        }

        It "Should enable JSON logging when specified" {
            Set-LogConfiguration -EnableJson
            $Global:EnableJsonLogging | Should -Be $true
        }
    }

    Context "Get-LogSummary" {
        BeforeEach {
            Start-Log -Path $testLogPath
        }

        It "Should count log entries correctly" {
            Write-Log -Type "Information" -Message "Info 1"
            Write-Log -Type "Information" -Message "Info 2"
            Write-Log -Type "Error" -Message "Error 1"
            Write-Log -Type "OK" -Message "OK 1"

            $summary = Get-LogSummary
            $summary.Information | Should -BeGreaterOrEqual 2
            $summary.Error | Should -Be 1
            $summary.OK | Should -Be 1
        }
    }
}

Describe "Config Module" {
    BeforeEach {
        Reset-Configuration
    }

    Context "Get-Configuration" {
        It "Should return default configuration" {
            $config = Get-Configuration
            $config | Should -Not -BeNullOrEmpty
            $config.lookbackDays | Should -Be 30
            $config.newAccountThresholdDays | Should -Be 7
        }

        It "Should cache configuration after first load" {
            $config1 = Get-Configuration
            $config2 = Get-Configuration
            $config1 | Should -Be $config2
        }
    }

    Context "Get-ConfigValue" {
        It "Should return top-level config values" {
            $value = Get-ConfigValue -KeyPath "lookbackDays"
            $value | Should -Be 30
        }

        It "Should return nested config values" {
            $value = Get-ConfigValue -KeyPath "riskLevels.critical"
            $value | Should -Be 9
        }

        It "Should return null for non-existent keys" {
            $value = Get-ConfigValue -KeyPath "nonexistent.key"
            $value | Should -BeNullOrEmpty
        }
    }

    Context "Reset-Configuration" {
        It "Should clear the cached configuration" {
            $config1 = Get-Configuration
            Reset-Configuration
            $global:AppConfig | Should -BeNullOrEmpty
        }
    }
}

Describe "HTML Tools Module" {
    Context "ConvertTo-HtmlSafeString" {
        It "Should escape HTML special characters" {
            $result = ConvertTo-HtmlSafeString '<script>alert("xss")</script>'
            $result | Should -Not -Match '<script>'
            $result | Should -Match '&lt;'
            $result | Should -Match '&gt;'
        }

        It "Should handle empty strings" {
            $result = ConvertTo-HtmlSafeString ""
            $result | Should -Be ""
        }

        It "Should handle null input" {
            $result = ConvertTo-HtmlSafeString $null
            $result | Should -Be ""
        }

        It "Should preserve safe text" {
            $result = ConvertTo-HtmlSafeString "Normal text without special chars"
            $result | Should -Be "Normal text without special chars"
        }
    }

    Context "Convert-ToHtmlTable" {
        It "Should return placeholder for empty data" {
            $result = Convert-ToHtmlTable -Data @()
            $result | Should -Match "No data available"
        }

        It "Should generate valid HTML table" {
            $data = @(
                [PSCustomObject]@{ Name = "Test"; Value = 123 }
            )
            $result = Convert-ToHtmlTable -Data $data
            $result | Should -Match "<table>"
            $result | Should -Match "<th>Name</th>"
            $result | Should -Match "<td>Test</td>"
        }

        It "Should escape HTML in data values" {
            $data = @(
                [PSCustomObject]@{ Name = "<script>bad</script>" }
            )
            $result = Convert-ToHtmlTable -Data $data
            $result | Should -Not -Match "<script>"
            $result | Should -Match "&lt;script&gt;"
        }
    }
}

Describe "Input Validation" {
    # Test the UPN validation function defined in main script
    BeforeAll {
        function Test-ValidUpnFormat {
            param([string]$Upn)
            return $Upn -match '^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        }
    }

    Context "Test-ValidUpnFormat" {
        It "Should accept valid UPN format" {
            Test-ValidUpnFormat -Upn "user@domain.com" | Should -Be $true
            Test-ValidUpnFormat -Upn "user.name@subdomain.domain.nl" | Should -Be $true
            Test-ValidUpnFormat -Upn "user+tag@domain.org" | Should -Be $true
        }

        It "Should reject invalid UPN format" {
            Test-ValidUpnFormat -Upn "notanemail" | Should -Be $false
            Test-ValidUpnFormat -Upn "@domain.com" | Should -Be $false
            Test-ValidUpnFormat -Upn "user@" | Should -Be $false
            Test-ValidUpnFormat -Upn "" | Should -Be $false
        }
    }
}
