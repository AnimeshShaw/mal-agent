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
