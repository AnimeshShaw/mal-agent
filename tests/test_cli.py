"""CLI: the mandatory txt report is written unconditionally -- --out has a
default rather than being skippable -- and output filenames are namespaced
by sample hash so multiple samples analyzed into the same default
directory don't silently overwrite each other's reports."""
from __future__ import annotations
from pathlib import Path
from malagent.cli import main


def _make_fake_pe(tmp: Path) -> str:
    body = (b"MZ" + b"\x00" * 64 +
            b"This program cannot be run in DOS mode.\n" +
            b"CreateRemoteThread VirtualAlloc WriteProcessMemory\n" +
            b"\x00" * 256)
    p = tmp / "fake_sample.bin"
    p.write_bytes(body)
    return str(p)


def test_txt_report_written_without_explicit_out(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    path = _make_fake_pe(tmp_path)
    rc = main([path, "--source", "dataset"])
    assert rc == 0
    default_dir = tmp_path / "mal-agent-reports"
    txt_files = list(default_dir.glob("*_report.txt"))
    assert len(txt_files) == 1
    content = txt_files[0].read_text()
    assert "MAL-AGENT DETAILED ANALYSIS REPORT" in content


def test_all_three_output_files_written_and_namespaced_by_sample(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    path = _make_fake_pe(tmp_path)
    rc = main([path, "--source", "dataset"])
    assert rc == 0
    default_dir = tmp_path / "mal-agent-reports"
    md_files = list(default_dir.glob("*_report.md"))
    json_files = list(default_dir.glob("*_verdict.json"))
    txt_files = list(default_dir.glob("*_report.txt"))
    assert len(md_files) == len(json_files) == len(txt_files) == 1
    # all three share the same sha256-derived prefix
    assert md_files[0].name.split("_report.md")[0] == txt_files[0].name.split("_report.txt")[0]


def test_explicit_out_still_respected(tmp_path):
    path = _make_fake_pe(tmp_path)
    custom_out = tmp_path / "custom"
    rc = main([path, "--source", "dataset", "--out", str(custom_out)])
    assert rc == 0
    assert list(custom_out.glob("*_report.txt"))


def test_two_different_samples_in_same_default_dir_do_not_overwrite(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    sample_dir_a = tmp_path / "a"
    sample_dir_a.mkdir()
    path_a = _make_fake_pe(sample_dir_a)
    sample_dir_b = tmp_path / "b"
    sample_dir_b.mkdir()
    path_b = sample_dir_b / "other_sample.bin"
    path_b.write_bytes(b"MZ" + b"\x11" * 200)  # different content -> different sha256

    assert main([path_a, "--source", "dataset"]) == 0
    assert main([str(path_b), "--source", "dataset"]) == 0

    default_dir = tmp_path / "mal-agent-reports"
    txt_files = sorted(default_dir.glob("*_report.txt"))
    assert len(txt_files) == 2


def test_doctor_subcommand_prints_report(capsys):
    main(["doctor"])
    captured = capsys.readouterr()
    assert "MAL-AGENT DOCTOR" in captured.out


def test_doctor_subcommand_returns_valid_exit_code():
    rc = main(["doctor"])
    assert rc in (0, 1)


def test_normal_analyze_invocation_still_works_unaffected(tmp_path, monkeypatch):
    """Backward compatibility: 'mal-agent <path>' must not be broken by
    doctor's addition -- 'doctor' is handled as a special case, not a
    subparser that could shadow the positional path argument."""
    monkeypatch.chdir(tmp_path)
    body = b"MZ" + b"\x00" * 64 + b"benign\n" + b"\x00" * 256
    p = tmp_path / "sample.bin"
    p.write_bytes(body)
    rc = main([str(p), "--source", "dataset"])
    assert rc == 0


class _FakeEvalReport:
    def __init__(self):
        self._total = 2


def test_evaluate_subcommand_prints_report(monkeypatch, tmp_path, capsys):
    manifest = tmp_path / "manifest.csv"
    manifest.write_text("path,label\n/a,benign\n/b,malicious\n")

    import malagent.evaluation as evaluation_module
    monkeypatch.setattr(evaluation_module, "evaluate", lambda samples, **kw: _FakeEvalReport())
    monkeypatch.setattr(evaluation_module, "format_report", lambda report: "FAKE EVAL REPORT TEXT")

    rc = main(["evaluate", str(manifest)])
    captured = capsys.readouterr()
    assert rc == 0
    assert "FAKE EVAL REPORT TEXT" in captured.out


def test_evaluate_subcommand_writes_out_file_when_requested(monkeypatch, tmp_path):
    manifest = tmp_path / "manifest.csv"
    manifest.write_text("path,label\n/a,benign\n")
    out_file = tmp_path / "results.txt"

    import malagent.evaluation as evaluation_module
    monkeypatch.setattr(evaluation_module, "evaluate", lambda samples, **kw: _FakeEvalReport())
    monkeypatch.setattr(evaluation_module, "format_report", lambda report: "FAKE EVAL REPORT TEXT")

    rc = main(["evaluate", str(manifest), "--out", str(out_file)])
    assert rc == 0
    assert out_file.read_text() == "FAKE EVAL REPORT TEXT"


def test_evaluate_subcommand_errors_on_missing_manifest(tmp_path):
    rc = main(["evaluate", str(tmp_path / "nope.csv")])
    assert rc == 2
