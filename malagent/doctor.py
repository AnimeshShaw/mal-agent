"""`mal-agent doctor`: verifies the real toolchain (Ghidra, capa+rules+sigs,
Ollama+model, cloud keys, Postgres, known-good allowlist) is actually
configured correctly, not just "present." Automates the manual
verification performed throughout this project's live-testing sessions
(docs/TODO.md M2 setup notes, docs/AUDIT.md). FAIL means something was
explicitly configured but doesn't work -- not mere absence of an optional
tool, which is WARN (or PASS, when the absence has a supported default,
like no DATABASE_URL falling back to the in-memory repository)."""
from __future__ import annotations
import json
import os
import shutil
import urllib.error
import urllib.request
from pathlib import Path
from typing import NamedTuple


class CheckResult(NamedTuple):
    name: str
    status: str  # "PASS" | "WARN" | "FAIL"
    detail: str


def check_pefile() -> CheckResult:
    try:
        import pefile  # noqa: F401
        return CheckResult("pefile", "PASS", "importable")
    except Exception:
        return CheckResult("pefile", "WARN",
                           "not installed -- PE import parsing disabled (pip install pefile)")


def check_capa() -> CheckResult:
    if not shutil.which("capa"):
        return CheckResult("capa", "WARN",
                           "not on PATH -- capability/ATT&CK triage disabled "
                           "(pip install flare-capa)")
    rules = os.getenv("CAPA_RULES_PATH")
    if not rules or not Path(rules).is_dir():
        return CheckResult("capa", "WARN",
                           "capa on PATH but CAPA_RULES_PATH is unset or invalid -- "
                           "capa will fail with 'rules not found'")
    sigs = os.getenv("CAPA_SIGS_PATH")
    if not sigs or not Path(sigs).is_dir():
        return CheckResult("capa", "WARN",
                           "capa on PATH with valid rules but CAPA_SIGS_PATH is unset "
                           "or invalid -- FLIRT-based function identification degraded")
    return CheckResult("capa", "PASS", f"rules={rules}, sigs={sigs}")


def check_floss() -> CheckResult:
    if not shutil.which("floss"):
        return CheckResult("floss", "WARN",
                           "not on PATH -- deobfuscated string extraction disabled "
                           "(pip install flare-floss; needs a C compiler toolchain -- "
                           "Microsoft C++ Build Tools on Windows -- to build its "
                           "binary2strings dependency)")
    return CheckResult("floss", "PASS", "on PATH")


def check_die() -> CheckResult:
    if not shutil.which("diec"):
        return CheckResult("die", "WARN",
                           "'diec' not on PATH -- packer/compiler identification disabled "
                           "(install from https://github.com/horsicq/DIE-engine)")
    return CheckResult("die", "PASS", "on PATH")


def check_virustotal() -> CheckResult:
    api_key = os.getenv("VIRUSTOTAL_API_KEY")
    if not api_key:
        return CheckResult("virustotal", "PASS", "not configured (optional)")
    try:
        import requests  # noqa: F401
    except Exception:
        return CheckResult("virustotal", "WARN",
                           "VIRUSTOTAL_API_KEY set but 'requests' not installed "
                           "(pip install requests)")
    return CheckResult("virustotal", "PASS",
                       "API key configured -- remember EgressPolicy.allow_hash_lookup "
                       "must also be True for lookups to actually run")


def check_ghidra() -> CheckResult:
    from .ghidra_tool import find_headless_ghidra
    home = os.getenv("GHIDRA_HOME")
    if not home:
        return CheckResult("ghidra", "WARN",
                           "GHIDRA_HOME not set -- per-function decompilation disabled")
    headless = find_headless_ghidra()
    if not headless:
        return CheckResult("ghidra", "FAIL",
                           f"GHIDRA_HOME={home} set but support/analyzeHeadless not found there")
    try:
        import pyghidra  # noqa: F401
    except Exception:
        return CheckResult("ghidra", "FAIL",
                           "GHIDRA_HOME is valid but pyghidra is not installed "
                           "(pip install pyghidra)")
    return CheckResult("ghidra", "PASS", f"GHIDRA_HOME={home}")


def check_java() -> CheckResult:
    if shutil.which("java"):
        return CheckResult("java", "PASS", "on PATH")
    if os.getenv("GHIDRA_HOME"):
        return CheckResult("java", "FAIL",
                           "GHIDRA_HOME is set but java is not on PATH -- Ghidra needs "
                           "a JVM (install JDK 21+)")
    return CheckResult("java", "WARN", "not on PATH -- only needed if using Ghidra")


def check_ollama() -> CheckResult:
    base = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")
    model = os.getenv("LOCAL_MODEL", "qwen3:8b")
    try:
        with urllib.request.urlopen(f"{base}/api/tags", timeout=3) as resp:
            data = json.loads(resp.read().decode("utf-8"))
    except (urllib.error.URLError, TimeoutError, OSError):
        return CheckResult("ollama", "WARN",
                           f"not reachable at {base} -- local model summarization disabled")
    names = [m.get("name", "") for m in data.get("models", [])]
    if model not in names and not any(n.startswith(model.split(":")[0]) for n in names):
        return CheckResult("ollama", "WARN",
                           f"reachable at {base} but model '{model}' not pulled "
                           f"(ollama pull {model})")
    return CheckResult("ollama", "PASS", f"{base}, model '{model}' available")


def check_cloud_keys() -> CheckResult:
    present = [name for name in ("OPENAI_API_KEY", "ANTHROPIC_API_KEY",
                                 "GEMINI_API_KEY", "XAI_API_KEY") if os.getenv(name)]
    if present:
        return CheckResult("cloud_keys", "PASS", f"configured: {', '.join(present)}")
    return CheckResult("cloud_keys", "WARN",
                       "no cloud provider API keys set -- escalation will fail closed "
                       "if triggered")


def check_database() -> CheckResult:
    from .store import get_repository, PostgresRepository
    if not os.getenv("DATABASE_URL"):
        return CheckResult("database", "PASS",
                           "DATABASE_URL not set -- using in-memory repository "
                           "(supported default)")
    repo = get_repository()
    if isinstance(repo, PostgresRepository):
        return CheckResult("database", "PASS", "connected")
    return CheckResult("database", "FAIL",
                       "DATABASE_URL is set but connection failed -- fell back to "
                       "in-memory repository")


def check_known_good_allowlist() -> CheckResult:
    from .knowngood import load_known_good_hashes
    path = os.getenv("KNOWN_GOOD_HASHES_PATH")
    if not path:
        return CheckResult("known_good_allowlist", "PASS", "not configured (optional)")
    hashes = load_known_good_hashes(path)
    if not hashes:
        return CheckResult("known_good_allowlist", "WARN",
                           f"{path} set but missing or empty -- no entries loaded")
    return CheckResult("known_good_allowlist", "PASS",
                       f"{len(hashes)} entries loaded from {path}")


def check_ioc_reputation() -> CheckResult:
    from .ioc_reputation import _load_list
    ip_path = os.getenv("IP_BLOCKLIST_PATH")
    domain_path = os.getenv("DOMAIN_BLOCKLIST_PATH")
    if not ip_path and not domain_path:
        return CheckResult("ioc_reputation", "PASS", "not configured (optional)")

    counts = []
    if ip_path:
        if not Path(ip_path).is_file():
            return CheckResult("ioc_reputation", "WARN",
                               f"IP_BLOCKLIST_PATH={ip_path} set but missing")
        counts.append(f"{len(_load_list(ip_path))} IPs")
    if domain_path:
        if not Path(domain_path).is_file():
            return CheckResult("ioc_reputation", "WARN",
                               f"DOMAIN_BLOCKLIST_PATH={domain_path} set but missing")
        counts.append(f"{len(_load_list(domain_path))} domains")
    return CheckResult("ioc_reputation", "PASS", ", ".join(counts) + " loaded")


def check_yara_match() -> CheckResult:
    path = os.getenv("YARA_RULES_PATH")
    if not path:
        return CheckResult("yara_match", "PASS", "not configured (optional)")
    p = Path(path)
    if not p.exists():
        return CheckResult("yara_match", "WARN", f"YARA_RULES_PATH={path} set but missing")
    try:
        import yara  # noqa: F401
    except Exception:
        return CheckResult("yara_match", "WARN",
                           f"{path} set but 'yara-python' not installed "
                           f"(pip install yara-python)")
    from .yara_match import _compile_rules
    try:
        rules = _compile_rules(path)
    except Exception as e:
        return CheckResult("yara_match", "FAIL", f"{path} set but failed to compile: {e}")
    if rules is None:
        return CheckResult("yara_match", "WARN", f"{path} set but no .yar/.yara files found")
    count = sum(1 for _ in rules)
    return CheckResult("yara_match", "PASS", f"{count} rule(s) compiled from {path}")


def check_ember() -> CheckResult:
    path = os.getenv("EMBER_MODEL_PATH")
    if not path:
        return CheckResult("ember_classifier", "PASS", "not configured (optional)")
    if not Path(path).exists():
        return CheckResult("ember_classifier", "WARN", f"EMBER_MODEL_PATH={path} set but missing")
    try:
        import lightgbm as lgb
        import thrember  # noqa: F401
    except Exception:
        return CheckResult("ember_classifier", "WARN",
                           f"{path} set but 'thrember'/'lightgbm' not installed "
                           f"(see docs/ML_CLASSIFIER_PLAN.md)")
    try:
        lgb.Booster(model_file=path)
    except Exception as e:
        return CheckResult("ember_classifier", "FAIL", f"{path} set but failed to load: {e}")
    return CheckResult("ember_classifier", "PASS", f"model loaded from {path}")


def _frontend_dist_dir() -> Path:
    """web/frontend/dist -- built via `npm run build` in web/frontend/,
    not committed (gitignored, like any build output). Factored out so
    tests can monkeypatch it instead of needing a real npm build on
    every test run."""
    return Path(__file__).resolve().parent.parent / "web" / "frontend" / "dist"


def check_web_ui() -> CheckResult:
    try:
        import fastapi  # noqa: F401
        import uvicorn  # noqa: F401
    except Exception:
        return CheckResult("web_ui", "WARN",
                           "fastapi/uvicorn not installed -- 'mal-agent web' unavailable "
                           "(pip install -e \".[web]\")")
    dist = _frontend_dist_dir()
    if not (dist / "index.html").is_file():
        return CheckResult("web_ui", "WARN",
                           f"backend deps installed but frontend not built at {dist} -- "
                           "'mal-agent web' would serve the JSON API only, no browser UI "
                           "(cd web/frontend && npm install && npm run build)")
    return CheckResult("web_ui", "PASS", f"backend + built frontend ready at {dist}")


def run_checks() -> list[CheckResult]:
    return [
        check_pefile(),
        check_capa(),
        check_floss(),
        check_ghidra(),
        check_java(),
        check_ollama(),
        check_cloud_keys(),
        check_database(),
        check_known_good_allowlist(),
        check_ioc_reputation(),
        check_yara_match(),
        check_die(),
        check_virustotal(),
        check_ember(),
        check_web_ui(),
    ]


def format_report(results: list[CheckResult]) -> str:
    lines = ["MAL-AGENT DOCTOR", "=" * 60]
    for r in results:
        lines.append(f"[{r.status:4s}] {r.name:24s} {r.detail}")
    fails = sum(1 for r in results if r.status == "FAIL")
    warns = sum(1 for r in results if r.status == "WARN")
    lines.append("=" * 60)
    lines.append(f"{fails} FAIL, {warns} WARN, {len(results) - fails - warns} PASS")
    return "\n".join(lines)


def exit_code(results: list[CheckResult]) -> int:
    return 1 if any(r.status == "FAIL" for r in results) else 0
