# One-off: gemma4:12b's own reliability-as-adjudicator run (the axis that was
# still pending after the qwen3:8b/gemma4:12b main+adversarial+reliability+claims
# pipeline finished on 2026-09-28). Same conventions as run_research_jobs.ps1:
# logs START/END to research_out\jobs.log so the existing watch script picks it
# up, and is safe to leave running detached.
Set-Location (Split-Path -Parent $PSScriptRoot)
if (-not $env:EMBER_MODEL_PATH) { $env:EMBER_MODEL_PATH = "D:\Tools\ember-models\EMBER2024_all.model" }
if (Test-Path Env:KNOWN_GOOD_HASHES_PATH) { Remove-Item Env:KNOWN_GOOD_HASHES_PATH }
$env:PYTHONIOENCODING = "utf-8"
New-Item -ItemType Directory -Force research_out\logs | Out-Null
$log = "research_out\jobs.log"
"[$(Get-Date -Format s)] START reliability ollama:gemma4:12b" | Out-File -Append -Encoding utf8 $log
python -m malagent.cli research judge-run --model ollama:gemma4:12b --exp reliability --split test --routed-only --limit 100 *>> research_out\logs\gemma_reliability.log
$code = $LASTEXITCODE
"[$(Get-Date -Format s)] END   reliability ollama:gemma4:12b (exit $code)" | Out-File -Append -Encoding utf8 $log
