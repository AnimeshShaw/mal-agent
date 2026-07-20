"""capa needs its rules (and optionally FLIRT signatures) supplied explicitly
-- a plain `pip install flare-capa` does not bundle them. `_capa_command()`
builds the CLI invocation, picking up CAPA_RULES_PATH/CAPA_SIGS_PATH from the
environment when set, so operators can point at a downloaded capa-rules
checkout without any code change."""
from __future__ import annotations
from malagent.tools import _capa_command


def test_no_env_vars_set_omits_rules_and_sigs_flags(monkeypatch):
    monkeypatch.delenv("CAPA_RULES_PATH", raising=False)
    monkeypatch.delenv("CAPA_SIGS_PATH", raising=False)
    assert _capa_command("sample.bin") == ["capa", "-j", "sample.bin"]


def test_rules_path_env_var_adds_r_flag(monkeypatch):
    monkeypatch.setenv("CAPA_RULES_PATH", "D:/Tools/capa-rules")
    monkeypatch.delenv("CAPA_SIGS_PATH", raising=False)
    cmd = _capa_command("sample.bin")
    assert cmd == ["capa", "-j", "-r", "D:/Tools/capa-rules", "sample.bin"]


def test_sigs_path_env_var_adds_s_flag(monkeypatch):
    monkeypatch.delenv("CAPA_RULES_PATH", raising=False)
    monkeypatch.setenv("CAPA_SIGS_PATH", "D:/Tools/capa-sigs")
    cmd = _capa_command("sample.bin")
    assert cmd == ["capa", "-j", "-s", "D:/Tools/capa-sigs", "sample.bin"]


def test_both_env_vars_set_adds_both_flags(monkeypatch):
    monkeypatch.setenv("CAPA_RULES_PATH", "D:/Tools/capa-rules")
    monkeypatch.setenv("CAPA_SIGS_PATH", "D:/Tools/capa-sigs")
    cmd = _capa_command("sample.bin")
    assert cmd == ["capa", "-j", "-r", "D:/Tools/capa-rules",
                   "-s", "D:/Tools/capa-sigs", "sample.bin"]
