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


def test_make_manifest_subcommand_writes_csv_and_reports_counts(tmp_path, capsys):
    (tmp_path / "benign").mkdir()
    (tmp_path / "malicious").mkdir()
    (tmp_path / "benign" / "a.exe").write_bytes(b"A")
    (tmp_path / "malicious" / "b.bin").write_bytes(b"B")

    rc = main(["make-manifest", str(tmp_path)])
    assert rc == 0
    manifest = tmp_path / "manifest.csv"
    assert manifest.exists()
    captured = capsys.readouterr()
    assert "1 benign" in captured.out
    assert "1 malicious" in captured.out


def test_make_manifest_subcommand_errors_cleanly_on_empty_dataset(tmp_path, capsys):
    (tmp_path / "benign").mkdir()
    (tmp_path / "malicious").mkdir()
    rc = main(["make-manifest", str(tmp_path)])
    assert rc == 2
    captured = capsys.readouterr()
    assert "no sample files found" in captured.err


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


def test_evaluate_subcommand_threads_local_model_through(monkeypatch, tmp_path):
    """--local-model lets you compare local models (e.g. against a
    calibration set) without editing code -- must actually reach
    evaluation.evaluate(), not just be accepted and dropped."""
    manifest = tmp_path / "manifest.csv"
    manifest.write_text("path,label\n/a,benign\n")

    captured_kwargs = {}
    import malagent.evaluation as evaluation_module

    def _fake_evaluate(samples, **kw):
        captured_kwargs.update(kw)
        return _FakeEvalReport()

    monkeypatch.setattr(evaluation_module, "evaluate", _fake_evaluate)
    monkeypatch.setattr(evaluation_module, "format_report", lambda report: "x")

    rc = main(["evaluate", str(manifest), "--enable-models", "--local-model", "gemma4:12b"])
    assert rc == 0
    assert captured_kwargs["local_model"] == "gemma4:12b"


def test_analyze_subcommand_threads_local_model_through(monkeypatch, tmp_path):
    captured_kwargs = {}

    class _FakeAudit:
        def verify(self):
            return True
        records = []

    class _FakeSample:
        sha256 = "a" * 64

    class _FakeState:
        sample = _FakeSample()

    def _fake_analyze(path, **kw):
        captured_kwargs.update(kw)
        from malagent.contracts import Verdict
        return _FakeState(), Verdict(sample_sha256="a" * 64, verdict="benign"), "md", "txt", _FakeAudit()

    monkeypatch.setattr("malagent.cli.analyze", _fake_analyze)
    p = tmp_path / "sample.bin"
    p.write_bytes(b"MZ" + b"\x00" * 64)

    rc = main([str(p), "--enable-models", "--local-model", "gemma4:12b", "--out", str(tmp_path / "out")])
    assert rc == 0
    assert captured_kwargs["local_model"] == "gemma4:12b"


class _FakeAblationReport:
    def __init__(self):
        self.results = [1, 2]


def test_ablate_critic_subcommand_prints_report(monkeypatch, capsys):
    import malagent.critic_ablation as ablation_module
    monkeypatch.setattr(ablation_module, "run_ablation", lambda cases, router: _FakeAblationReport())
    monkeypatch.setattr(ablation_module, "format_report", lambda report: "FAKE ABLATION REPORT TEXT")

    rc = main(["ablate-critic"])
    captured = capsys.readouterr()
    assert rc == 0
    assert "FAKE ABLATION REPORT TEXT" in captured.out


def test_ablate_critic_subcommand_writes_out_file_when_requested(monkeypatch, tmp_path):
    import malagent.critic_ablation as ablation_module
    monkeypatch.setattr(ablation_module, "run_ablation", lambda cases, router: _FakeAblationReport())
    monkeypatch.setattr(ablation_module, "format_report", lambda report: "FAKE ABLATION REPORT TEXT")

    out_file = tmp_path / "ablation.txt"
    rc = main(["ablate-critic", "--out", str(out_file)])
    assert rc == 0
    assert out_file.read_text() == "FAKE ABLATION REPORT TEXT"
