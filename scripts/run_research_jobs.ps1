# Reproduces the paper's local-model experiments end to end, unattended.
# Launch detached so it survives terminal/session exits:
#   Start-Process powershell -WindowStyle Hidden -ArgumentList '-NoProfile','-File','scripts\run_research_jobs.ps1'
# Every step is resumable (bundles skip existing files; judge runs skip
# recorded (sample, variant) pairs; generations are disk-cached), so
# re-launching after an interruption only does the remaining work.
# Frontier models: re-run the judge-run / judge-claims lines with e.g.
#   --model anthropic:claude-opus-5-5   (needs ANTHROPIC_API_KEY)
#
# -Workers default is 4, not higher: each worker loads the EMBER/LightGBM
# classifier plus capa/Ghidra subprocesses, and a real incident on this
# 16GB machine showed 12 parallel workers exhausting RAM (OpenBLAS's
# allocator giving up), crashing the pool. build-bundles itself now
# recovers from a crashed pool (see malagent/judge/collect.py), but this
# script still stops on a critical-step failure below rather than
# pressing on to score judge experiments against a dataset it never
# confirmed was complete -- which is exactly what let a real, invalid
# partial-dataset run through undetected on 2026-09-28.
param(
    [string]$Models = "ollama:qwen3:8b,ollama:gemma4:12b",
    [int]$Workers = 4
)
$ErrorActionPreference = "Continue"
Set-Location (Split-Path -Parent $PSScriptRoot)
New-Item -ItemType Directory -Force research_out | Out-Null
$log = "research_out\jobs.log"

function Step($name, [scriptblock]$body, [bool]$critical = $false) {
    "[$(Get-Date -Format s)] START $name" | Out-File -Append -Encoding utf8 $log
    & $body *>> $log
    $code = $LASTEXITCODE
    "[$(Get-Date -Format s)] END   $name (exit $code)" | Out-File -Append -Encoding utf8 $log
    if ($critical -and $code -ne 0) {
        "[$(Get-Date -Format s)] STOPPING: critical step '$name' exited $code -- refusing to " +
        "score judge experiments against a dataset that was never confirmed complete. Re-run " +
        "this script (same args) to resume; already-built bundles and cached generations are kept." |
            Out-File -Append -Encoding utf8 $log
        exit 1
    }
}

if (-not $env:EMBER_MODEL_PATH) { $env:EMBER_MODEL_PATH = "D:\Tools\ember-models\EMBER2024_all.model" }
Remove-Item Env:KNOWN_GOOD_HASHES_PATH -ErrorAction SilentlyContinue
$env:PYTHONIOENCODING = "utf-8"

Step "manifest" { python scripts\make_manifest_v2.py } $true
Step "bundles" { python -m malagent.cli research build-bundles dataset\manifest_v2.csv --out bundles\v2 --workers $Workers --capa-timeout 150 } $true

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
