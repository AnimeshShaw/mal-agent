# One-off: wait for the Gemini 3.1 Pro daily request quota (250/day) to reset,
# then resume the resumable main-experiment run. Detached, survives sessions.
# Reset estimated ~05:30 IST 2026-10-08 from the 429 retryDelay.
Set-Location (Split-Path -Parent $PSScriptRoot)
$target = Get-Date "2026-10-08 05:35:00"
while ((Get-Date) -lt $target) { Start-Sleep -Seconds 300 }

$envLine = Get-Content .env | Where-Object { $_ -match '^GEMINI_API_KEY=' }
$env:GEMINI_API_KEY = ($envLine -split '=', 2)[1].Trim()

# Retry a tiny test call every 15 minutes until the quota accepts requests.
$ok = $false
for ($i = 0; $i -lt 40 -and -not $ok; $i++) {
    $out = python -I -c "from google import genai; print(genai.Client().models.generate_content(model='gemini-3.1-pro-preview', contents='ok').text)" 2>&1
    if ($LASTEXITCODE -eq 0) { $ok = $true } else { Start-Sleep -Seconds 900 }
}
"[$(Get-Date -Format s)] resume check: quota ok=$ok" | Out-File -Append -Encoding utf8 research_out\jobs.log
if ($ok) {
    & powershell -NoProfile -File scripts\run_gemini_main.ps1
}
