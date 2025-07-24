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
function Invoke-OpenAIAdvisory {
# 🔒 Import OpenAI apikey
# Load local OpenAI key if available, else public.
if (Test-Path "$PSScriptRoot\..\api\apikey_openai_local.ps1") {
    . "$PSScriptRoot\..\api\apikey_openai_local.ps1"
} else {
    . "$PSScriptRoot\..\api\apikey_openai.ps1"
}

if (-not $apiKey -or $apiKey -like '*<*') {
        Write-Host "❌ No valid OpenAI API key configured in module." -ForegroundColor Red
        Write-Log -Type "Error" -Message "OpenAI API key is missing or invalid."
        return
    }

    # 🌐 Define the OpenAI API endpoint and authentication headers
    # Required to submit the chat completion request to the GPT model.
    $uri = "https://api.openai.com/v1/chat/completions"
    $headers = @{
        "Authorization" = "Bearer $apiKey"
        "Content-Type"  = "application/json"
    }


# 🧠 Build up messages in 5 parts to avoid token overload and provide structured context

# 1. Instruction message (wait for all data)
$messages = @(
    @{ role = 'system'; content = 'You are a helpful cybersecurity assistant.' },
    @{ role = 'user'; content = @'
You are a cyber threat analyst. The relevant data and instructions will follow in five separate messages:
1. UserRisk
2. SignInRisk
3. AuditLogs
4. ConditionalAccess
5. Instuctions

Wait to analyze until you received the final prompt with instructions and keep the formatting intact.
Do not respond until then.
'@ }
)

# 2. UserRisk JSON
if ($global:aiadvisory.UserRisk) {
    $userRiskJson = $global:aiadvisory.UserRisk | ConvertTo-Json -Depth 10
} else {
    $userRiskJson = "{}"
    Write-Log -Type "Information" -Message "ℹ️ No UserRisk data found — sending empty object to OpenAI."
}
$messages += @{ role = 'user'; content = $userRiskJson }
$userRiskJson | Out-File "$global:jsonExportFolder\UserRisk.json" -Encoding UTF8

# 3. SignInRisk JSON
if ($global:aiadvisory.SignInRisk) {
    $signInRiskJson = $global:aiadvisory.SignInRisk | ConvertTo-Json -Depth 10
} else {
    $signInRiskJson = "{}"
    Write-Log -Type "Information" -Message "ℹ️ No SignInRisk data found — sending empty object to OpenAI."
}
$messages += @{ role = 'user'; content = $signInRiskJson }
$signInRiskJson | Out-File "$global:jsonExportFolder\SigninRisk.json" -Encoding UTF8

# 4. AuditLogs JSON
if ($global:aiadvisory.AuditLogs) {
    $auditLogsJson = $global:aiadvisory.AuditLogs | ConvertTo-Json -Depth 10
} else {
    $auditLogsJson = "{}"
    Write-Log -Type "Information" -Message "ℹ️ No AuditLogs data found — sending empty object to OpenAI."
}
$messages += @{ role = 'user'; content = $auditLogsJson }
$auditLogsJson | Out-File "$global:jsonExportFolder\AuditLogs.json" -Encoding UTF8

# 5. ConditionalAccess JSON
if ($global:aiadvisory.CA) {
    $caJson = $global:aiadvisory.CA | ConvertTo-Json -Depth 10
} else {
    $caJson = "{}"
    Write-Log -Type "Information" -Message "ℹ️ No ConditionalAccess data found — sending empty object to OpenAI."
}
$messages += @{ role = 'user'; content = $caJson }
$caJson | Out-File "$global:jsonExportFolder\CA.json" -Encoding UTF8


# 6. Final instruction to start analysis
$overallPrompt  = @'
Analyze for possible relationships between risk factors — such as signs of lateral movement, persistence tactics, or privilege abuse. Highlight only if patterns suggest active exploitation vs misconfiguration.

You must wait for all JSON input before beginning analysis. The advisory must be based *only* on what is explicitly stated in the provided JSON. Do not speculate, extrapolate, or generalize.

❗ Strict validation rules:
- If a risk factor is **not present** in the data, do not mention it.
- If a value is `"Not applicable"`, treat it as if it does **not exist**. Never mention or recommend action for it.
- If the JSON contains no risks (or only "Not applicable" entries), your advisory must reflect that.
- You may not recommend actions unless there is confirmed evidence in `UserRisk`, `SignInRisk` (score ≥ 1), or `AuditLogs`.

⚠️ Violations of these rules will be treated as critical errors:
- Do not mention "OAuth", "Inbox Rules", "No MFA", "Admin Role", or any other known risks **unless** they are explicitly present in the data and not marked "Not applicable".
- Do not recommend anything based on standard best practices, speculation, or assumptions.
- Do not hallucinate context or behavior that is not supported in the JSON.

Also incorporate `AuditLogs` if provided, especially events related to password resets, MFA changes, role assignments, or configuration changes.

If Conditional Access (CA) policies were applied or modified **after** a risky sign-in occurred, consider the risk as **historically valid but currently mitigated**. Clearly reflect this timeline-based mitigation in the output.

---

Use this exact format in your response:

📊 **Overall Risk Score:** X / 10  
<Score = (UserRiskScore + Average(SignInRisk.Score)) ÷ 2. Round to 1 decimal. No trailing ".0".>

📋 **Overall Risk Assessment**  
<Short summary (max 400 words) of the user's combined risk profile. Classify posture using the Risk Score:  
1 = Very Low Risk  
2–3 = Low Risk  
4–6 = Medium Risk  
7–8 = High Risk  
9–10 = Very High Risk  
Clearly indicate if the risk is driven by user configuration, session anomalies, or both. Include note if risks are now mitigated by Conditional Access.>

🎯 **Attack Profile Summary**  
<Describe likely attack patterns based on confirmed session behavior and configuration. Include possible tactics like persistence, privilege abuse, or lateral movement. Max 450 words.>

🔧 **Recommended Actions**  
Only include if supported by explicit risk data. Follow this format **exactly**:

**Risk Addressed:** <short risk label>  
**Trigger:** <event or evidence> (Source: UserRisk | SignInRisk | AuditLogs)  
**Action:** <plain English explanation, max 100 words>

⚠️ Do not use bold or styling for the Action line.  
⚠️ Never omit or merge fields. All three fields are mandatory.  
⚠️ Do not generate any action for entries marked "Not applicable".

🧱 **Conditional Access Policy Evaluation**

Only evaluate Conditional Access (CA) policies that apply to the user’s actual sign-ins.  
- Ignore policies unrelated to the user (e.g., guest/admin unless applicable).  
- Accept disabled policies only if they *would have applied*, but clearly state their status.  
- If risky sign-ins lacked protection earlier, but CA now mitigates that, say:  
  *“This risk has since been mitigated by current CA policy enforcement.”*

Make CA policy names **bold**, but do not use any other markdown.  
Do not suggest changes if CA already covers the risk.  
Do not include CA policies unrelated to observed user behavior.

'@
$messages += @{ role = 'user'; content = $overallPrompt }

    # 📨 Structure the chat message sequence for the OpenAI model

    # 📤 Build the request body for the OpenAI API call
    # 🤖 Dynamically choose OpenAI model based on risk volume
    if (
        $global:aiadvisory.SignInRisk.Count -ge 3 -or 
        $global:aiadvisory.UserRisk.Count -ge 1
    ) {
        $modelToUse = 'gpt-4-0125-preview'
        Write-Log -Type "Information" -Message "🧠 Using GPT-4.1 (gpt-4-0125-preview) for advisory generation due to elevated risk context."
    } else {
        $modelToUse = 'gpt-4-0125-preview'
        Write-Log -Type "Information" -Message "💡 Using GPT-3.5 Turbo for advisory generation – low-risk context detected."
    }

    # ✉️ Prepare OpenAI request body
    $overallBody = @{
        model       = $modelToUse
        messages    = $messages
        temperature = 0.0
    } | ConvertTo-Json -Depth 10

    $debugPath = Join-Path $global:jsonExportFolder "openai_input_messages.json"
    $messages | ConvertTo-Json -Depth 10 | Out-File $debugPath -Encoding UTF8

    # 🚀 Submit the request and handle the response
    # The advisory is stored in both OverallSummary and full Advisory for use in reports.
    try {
        Write-Log -Type "Information" -Message "Sending advisory request to OpenAI (GPT-3.5)..."
        $response = Invoke-RestMethod -Uri $uri -Method POST -Headers $headers -Body $overallBody -TimeoutSec 90

        $global:aiadvisory.OverallSummary = $response.choices[0].message.content.Trim()
        $global:aiadvisory.Advisory       = $global:aiadvisory.OverallSummary

        Write-Host "✅ Advisory generated successfully." -ForegroundColor Green
        Write-Log -Type "Information" -Message "OpenAI advisory generated and stored successfully."
    }
    catch {
        # 🛑 Log and store the error in case of failure
        Write-Host "⚠️ Failed to generate advisory: $_" -ForegroundColor Yellow
        $global:aiadvisory.Advisory = "Error generating advisory: $_"
        Write-Log -Type "Error" -Message ("OpenAI advisory request failed: {0}" -f $_)
    }
}