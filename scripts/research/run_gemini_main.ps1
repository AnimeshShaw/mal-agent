# One-off: the frontier-model arm the paper's Limitations section has been
# flagging as pending all session ("frontier-model arms need API credentials
# not configured"). User supplied a real GEMINI_API_KEY in .env on
# 2026-09-29. Real money: Gemini 3.1 Pro Preview is $2/$12 per 1M input/output
# tokens (output includes billed "thinking" tokens). Scoped to the MAIN
# experiment only (681 calls, est. $9-20) as a bounded first step -- NOT the
# full battery (main+adversarial+reliability, ~2741 calls, est. $35-80) --
# so real cost is known before deciding whether to spend more.
Set-Location (Split-Path -Parent $PSScriptRoot)
if (-not $env:EMBER_MODEL_PATH) { $env:EMBER_MODEL_PATH = "D:\Tools\ember-models\EMBER2024_all.model" }
if (Test-Path Env:KNOWN_GOOD_HASHES_PATH) { Remove-Item Env:KNOWN_GOOD_HASHES_PATH }
$env:PYTHONIOENCODING = "utf-8"

# Load GEMINI_API_KEY out of .env without a dotenv dependency.
$envLine = Get-Content .env | Where-Object { $_ -match '^GEMINI_API_KEY=' }
if ($envLine) { $env:GEMINI_API_KEY = ($envLine -split '=', 2)[1].Trim() }
if (-not $env:GEMINI_API_KEY) {
    "[$(Get-Date -Format s)] ABORT: GEMINI_API_KEY not found in .env" | Out-File -Append -Encoding utf8 research_out\jobs.log
    exit 1
}

New-Item -ItemType Directory -Force research_out\logs | Out-Null
$log = "research_out\jobs.log"
"[$(Get-Date -Format s)] START main gemini:gemini-3.1-pro-preview" | Out-File -Append -Encoding utf8 $log
python -m malagent.cli research judge-run --model gemini:gemini-3.1-pro-preview --exp main --split test *>> research_out\logs\gemini_main.log
$code = $LASTEXITCODE
"[$(Get-Date -Format s)] END   main gemini:gemini-3.1-pro-preview (exit $code)" | Out-File -Append -Encoding utf8 $log
