# One-off: gemma4:12b's own adversarial-robustness-as-adjudicator run -- the
# last remaining axis after qwen3:8b's adversarial+reliability and gemma4:12b's
# own reliability (2026-09-29) already completed. Same conventions as
# run_research_jobs.ps1 / run_gemma_reliability.ps1: logs START/END to
# research_out\jobs.log, safe to leave running detached.
Set-Location (Split-Path -Parent $PSScriptRoot)
if (-not $env:EMBER_MODEL_PATH) { $env:EMBER_MODEL_PATH = "D:\Tools\ember-models\EMBER2024_all.model" }
if (Test-Path Env:KNOWN_GOOD_HASHES_PATH) { Remove-Item Env:KNOWN_GOOD_HASHES_PATH }
$env:PYTHONIOENCODING = "utf-8"
New-Item -ItemType Directory -Force research_out\logs | Out-Null
$log = "research_out\jobs.log"
"[$(Get-Date -Format s)] START adversarial ollama:gemma4:12b" | Out-File -Append -Encoding utf8 $log
python -m malagent.cli research judge-run --model ollama:gemma4:12b --exp adversarial --split test --routed-only --limit 160 *>> research_out\logs\gemma_adversarial.log
$code = $LASTEXITCODE
"[$(Get-Date -Format s)] END   adversarial ollama:gemma4:12b (exit $code)" | Out-File -Append -Encoding utf8 $log
