# Reproduces the paper's local-model experiments end to end, unattended.
# Launch detached so it survives terminal/session exits:
#   Start-Process powershell -WindowStyle Hidden -ArgumentList '-NoProfile','-File','scripts\run_research_jobs.ps1'
# Every step is resumable (bundles skip existing files; judge runs skip
# recorded (sample, variant) pairs; generations are disk-cached), so
# re-launching after an interruption only does the remaining work.
# Frontier models: re-run the judge-run / judge-claims lines with e.g.
#   --model anthropic:claude-opus-5-5   (needs ANTHROPIC_API_KEY)
param(
    [string]$Models = "ollama:qwen3:8b,ollama:gemma4:12b",
    [int]$Workers = 12
)
$ErrorActionPreference = "Continue"
Set-Location (Split-Path -Parent $PSScriptRoot)
New-Item -ItemType Directory -Force research_out | Out-Null
$log = "research_out\jobs.log"
function Step($name, [scriptblock]$body) {
    "[$(Get-Date -Format s)] START $name" | Out-File -Append -Encoding utf8 $log
    & $body *>> $log
    "[$(Get-Date -Format s)] END   $name (exit $LASTEXITCODE)" | Out-File -Append -Encoding utf8 $log
}
if (-not $env:EMBER_MODEL_PATH) { $env:EMBER_MODEL_PATH = "D:\Tools\ember-models\EMBER2024_all.model" }
Remove-Item Env:KNOWN_GOOD_HASHES_PATH -ErrorAction SilentlyContinue
$env:PYTHONIOENCODING = "utf-8"

Step "manifest" { python scripts\make_manifest_v2.py }
Step "bundles" { python -m malagent.cli research build-bundles dataset\manifest_v2.csv --out bundles\v2 --workers $Workers --capa-timeout 150 }

$list = $Models.Split(",")
foreach ($m in $list) {
    Step "main $m" { python -m malagent.cli research judge-run --model $m --exp main --split test }
}
$first = $list[0]
Step "adversarial $first" { python -m malagent.cli research judge-run --model $first --exp adversarial --split test --routed-only --limit 160 }
Step "reliability $first" { python -m malagent.cli research judge-run --model $first --exp reliability --split test --routed-only --limit 100 }
if ($list.Count -gt 1) {
    Step "claims" { python -m malagent.cli research judge-claims --narrator $list[1] --judge $first --split test --limit 60 }
}
Step "report" { python -m malagent.cli research judge-report --split test }
"[$(Get-Date -Format s)] ALL DONE" | Out-File -Append -Encoding utf8 $log
