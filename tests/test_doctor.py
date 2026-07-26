"""mal-agent doctor: verifies the real toolchain is actually configured
correctly, not just "present." FAIL means something was explicitly
configured but doesn't work; WARN means an optional tool simply isn't set
up; PASS means it works, or is intentionally/safely absent (e.g. no
DATABASE_URL -> the supported in-memory-repository default)."""
from __future__ import annotations
import json
import os
from malagent import doctor


# ---------- check_pefile ----------

def test_pefile_installed_passes():
    result = doctor.check_pefile()
    assert result.status == "PASS"


# ---------- check_capa ----------

def test_capa_not_on_path_warns(monkeypatch):
    monkeypatch.setattr("shutil.which", lambda name: None)
    result = doctor.check_capa()
    assert result.status == "WARN"
    assert "not on PATH" in result.detail


def test_capa_on_path_but_no_rules_warns(monkeypatch):
    monkeypatch.setattr("shutil.which", lambda name: "/usr/bin/capa")
    monkeypatch.delenv("CAPA_RULES_PATH", raising=False)
    result = doctor.check_capa()
    assert result.status == "WARN"
    assert "CAPA_RULES_PATH" in result.detail


def test_capa_fully_configured_passes(monkeypatch, tmp_path):
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    sigs_dir = tmp_path / "sigs"
    sigs_dir.mkdir()
    monkeypatch.setattr("shutil.which", lambda name: "/usr/bin/capa")
    monkeypatch.setenv("CAPA_RULES_PATH", str(rules_dir))
    monkeypatch.setenv("CAPA_SIGS_PATH", str(sigs_dir))
    result = doctor.check_capa()
    assert result.status == "PASS"


# ---------- check_ghidra ----------

def test_ghidra_home_unset_warns(monkeypatch):
    monkeypatch.delenv("GHIDRA_HOME", raising=False)
    result = doctor.check_ghidra()
    assert result.status == "WARN"


def test_ghidra_home_set_but_invalid_fails(monkeypatch, tmp_path):
    monkeypatch.setenv("GHIDRA_HOME", str(tmp_path))  # no support/analyzeHeadless inside
    result = doctor.check_ghidra()
    assert result.status == "FAIL"


# ---------- check_java ----------

def test_java_missing_without_ghidra_warns(monkeypatch):
    monkeypatch.setattr("shutil.which", lambda name: None)
    monkeypatch.delenv("GHIDRA_HOME", raising=False)
    result = doctor.check_java()
    assert result.status == "WARN"


def test_java_missing_with_ghidra_configured_fails(monkeypatch, tmp_path):
    monkeypatch.setattr("shutil.which", lambda name: None)
    monkeypatch.setenv("GHIDRA_HOME", str(tmp_path))
    result = doctor.check_java()
    assert result.status == "FAIL"


# ---------- check_ollama ----------

def test_ollama_unreachable_warns(monkeypatch):
    def raise_urlerror(*a, **kw):
        import urllib.error
        raise urllib.error.URLError("connection refused")
    monkeypatch.setattr("urllib.request.urlopen", raise_urlerror)
    result = doctor.check_ollama()
    assert result.status == "WARN"


def test_ollama_reachable_with_model_pulled_passes(monkeypatch):
    class _FakeResponse:
        def read(self):
            return json.dumps({"models": [{"name": "qwen2.5-coder:7b"}]}).encode()

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    monkeypatch.setattr("urllib.request.urlopen", lambda *a, **kw: _FakeResponse())
    monkeypatch.setenv("LOCAL_MODEL", "qwen2.5-coder:7b")
    result = doctor.check_ollama()
    assert result.status == "PASS"


def test_ollama_reachable_without_model_pulled_warns(monkeypatch):
    class _FakeResponse:
        def read(self):
            return json.dumps({"models": []}).encode()

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    monkeypatch.setattr("urllib.request.urlopen", lambda *a, **kw: _FakeResponse())
    monkeypatch.setenv("LOCAL_MODEL", "qwen2.5-coder:7b")
    result = doctor.check_ollama()
    assert result.status == "WARN"
    assert "not pulled" in result.detail


# ---------- check_cloud_keys ----------

def test_no_cloud_keys_warns(monkeypatch):
    for k in ("OPENAI_API_KEY", "ANTHROPIC_API_KEY", "GEMINI_API_KEY", "XAI_API_KEY"):
        monkeypatch.delenv(k, raising=False)
    result = doctor.check_cloud_keys()
    assert result.status == "WARN"


def test_cloud_key_present_passes_and_never_shows_value(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-super-secret-value")
    for k in ("OPENAI_API_KEY", "GEMINI_API_KEY", "XAI_API_KEY"):
        monkeypatch.delenv(k, raising=False)
    result = doctor.check_cloud_keys()
    assert result.status == "PASS"
    assert "ANTHROPIC_API_KEY" in result.detail
    assert "sk-super-secret-value" not in result.detail


# ---------- check_database ----------

def test_database_url_unset_passes(monkeypatch):
    monkeypatch.delenv("DATABASE_URL", raising=False)
    result = doctor.check_database()
    assert result.status == "PASS"
    assert "in-memory" in result.detail


# ---------- check_known_good_allowlist ----------

def test_known_good_not_configured_passes(monkeypatch):
    monkeypatch.delenv("KNOWN_GOOD_HASHES_PATH", raising=False)
    result = doctor.check_known_good_allowlist()
    assert result.status == "PASS"
    assert "not configured" in result.detail


def test_known_good_configured_with_entries_passes(monkeypatch, tmp_path):
    p = tmp_path / "hashes.txt"
    p.write_text("a" * 64 + "\n")
    monkeypatch.setenv("KNOWN_GOOD_HASHES_PATH", str(p))
    result = doctor.check_known_good_allowlist()
    assert result.status == "PASS"
    assert "1 entries" in result.detail


def test_known_good_configured_but_missing_file_warns(monkeypatch, tmp_path):
    monkeypatch.setenv("KNOWN_GOOD_HASHES_PATH", str(tmp_path / "nope.txt"))
    result = doctor.check_known_good_allowlist()
    assert result.status == "WARN"


# ---------- check_ioc_reputation ----------

def test_ioc_reputation_not_configured_passes(monkeypatch):
    monkeypatch.delenv("IP_BLOCKLIST_PATH", raising=False)
    monkeypatch.delenv("DOMAIN_BLOCKLIST_PATH", raising=False)
    result = doctor.check_ioc_reputation()
    assert result.status == "PASS"
    assert "not configured" in result.detail


def test_ioc_reputation_configured_with_entries_passes(monkeypatch, tmp_path):
    p = tmp_path / "ips.txt"
    p.write_text("1.2.3.4\n")
    monkeypatch.setenv("IP_BLOCKLIST_PATH", str(p))
    monkeypatch.delenv("DOMAIN_BLOCKLIST_PATH", raising=False)
    result = doctor.check_ioc_reputation()
    assert result.status == "PASS"
    assert "1 " in result.detail


def test_ioc_reputation_configured_but_missing_file_warns(monkeypatch, tmp_path):
    monkeypatch.setenv("IP_BLOCKLIST_PATH", str(tmp_path / "nope.txt"))
    monkeypatch.delenv("DOMAIN_BLOCKLIST_PATH", raising=False)
    result = doctor.check_ioc_reputation()
    assert result.status == "WARN"


# ---------- check_yara_match ----------

def test_yara_match_not_configured_passes(monkeypatch):
    monkeypatch.delenv("YARA_RULES_PATH", raising=False)
    result = doctor.check_yara_match()
    assert result.status == "PASS"
    assert "not configured" in result.detail


def test_yara_match_configured_with_valid_rule_passes(monkeypatch, tmp_path):
    p = tmp_path / "test.yar"
    p.write_text('rule x { strings: $a = "y" condition: $a }')
    monkeypatch.setenv("YARA_RULES_PATH", str(p))
    result = doctor.check_yara_match()
    assert result.status == "PASS"
    assert "1 rule" in result.detail


def test_yara_match_configured_but_missing_path_warns(monkeypatch, tmp_path):
    monkeypatch.setenv("YARA_RULES_PATH", str(tmp_path / "nope.yar"))
    result = doctor.check_yara_match()
    assert result.status == "WARN"


def test_yara_match_configured_but_invalid_syntax_fails(monkeypatch, tmp_path):
    p = tmp_path / "bad.yar"
    p.write_text("not valid yara {{{")
    monkeypatch.setenv("YARA_RULES_PATH", str(p))
    result = doctor.check_yara_match()
    assert result.status == "FAIL"


# ---------- run_checks / format_report / exit_code ----------

def test_run_checks_returns_all_twelve_checks():
    results = doctor.run_checks()
    assert len(results) == 12
    assert {r.name for r in results} == {
        "pefile", "capa", "ghidra", "java", "ollama", "floss",
        "cloud_keys", "database", "known_good_allowlist", "ioc_reputation",
        "yara_match", "die",
    }


# ---------- check_floss ----------

def test_floss_not_on_path_warns(monkeypatch):
    monkeypatch.setattr("shutil.which", lambda name: None)
    result = doctor.check_floss()
    assert result.status == "WARN"
    assert "not on PATH" in result.detail


def test_floss_on_path_passes(monkeypatch):
    monkeypatch.setattr("shutil.which", lambda name: "/usr/bin/floss")
    result = doctor.check_floss()
    assert result.status == "PASS"


# ---------- check_die ----------

def test_die_not_on_path_warns(monkeypatch):
    monkeypatch.setattr("shutil.which", lambda name: None)
    result = doctor.check_die()
    assert result.status == "WARN"
    assert "not on PATH" in result.detail


def test_die_on_path_passes(monkeypatch):
    monkeypatch.setattr("shutil.which", lambda name: "/usr/bin/diec")
    result = doctor.check_die()
    assert result.status == "PASS"


def test_exit_code_zero_when_no_fail():
    results = [doctor.CheckResult("x", "PASS", ""), doctor.CheckResult("y", "WARN", "")]
    assert doctor.exit_code(results) == 0


def test_exit_code_nonzero_when_any_fail():
    results = [doctor.CheckResult("x", "PASS", ""), doctor.CheckResult("y", "FAIL", "")]
    assert doctor.exit_code(results) == 1


def test_format_report_includes_summary_counts():
    results = [doctor.CheckResult("x", "PASS", "ok"), doctor.CheckResult("y", "FAIL", "broken")]
    report = doctor.format_report(results)
    assert "1 FAIL" in report
    assert "x" in report and "ok" in report
    assert "y" in report and "broken" in report
