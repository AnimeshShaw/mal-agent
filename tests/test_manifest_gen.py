"""Generates the labeled-sample manifest CSV that 'mal-agent evaluate'
consumes, by scanning a dataset directory laid out as <root>/benign/*
and <root>/malicious/*. Removes the friction of hand-writing a CSV for
every sample."""
from __future__ import annotations
import csv
from pathlib import Path
from malagent.manifest_gen import scan_dataset_dir, write_manifest


def _make_dataset(tmp_path: Path) -> Path:
    (tmp_path / "benign").mkdir()
    (tmp_path / "malicious").mkdir()
    (tmp_path / "benign" / "a.exe").write_bytes(b"A")
    (tmp_path / "benign" / "b.dll").write_bytes(b"B")
    (tmp_path / "malicious" / "c.bin").write_bytes(b"C")
    return tmp_path


def test_scan_dataset_dir_finds_benign_and_malicious_files(tmp_path):
    root = _make_dataset(tmp_path)
    pairs = scan_dataset_dir(str(root))
    labels = sorted((Path(p).name, label) for p, label in pairs)
    assert labels == [("a.exe", "benign"), ("b.dll", "benign"), ("c.bin", "malicious")]


def test_scan_dataset_dir_returns_absolute_resolved_paths(tmp_path):
    root = _make_dataset(tmp_path)
    pairs = scan_dataset_dir(str(root))
    for path, _ in pairs:
        assert Path(path).is_absolute()
        assert Path(path).exists()


def test_scan_dataset_dir_ignores_subdirectories_within_label_folders(tmp_path):
    root = _make_dataset(tmp_path)
    (root / "benign" / "nested").mkdir()
    pairs = scan_dataset_dir(str(root))
    names = {Path(p).name for p, _ in pairs}
    assert "nested" not in names


def test_scan_dataset_dir_raises_when_no_samples_found(tmp_path):
    (tmp_path / "benign").mkdir()
    (tmp_path / "malicious").mkdir()
    try:
        scan_dataset_dir(str(tmp_path))
        assert False, "expected ValueError"
    except ValueError as e:
        assert "no sample files found" in str(e)


def test_scan_dataset_dir_raises_when_label_folders_missing(tmp_path):
    try:
        scan_dataset_dir(str(tmp_path))
        assert False, "expected ValueError"
    except ValueError:
        pass


def test_write_manifest_produces_a_csv_loadable_by_evaluation(tmp_path):
    root = _make_dataset(tmp_path)
    pairs = scan_dataset_dir(str(root))
    out = tmp_path / "manifest.csv"
    write_manifest(pairs, str(out))

    from malagent.evaluation import load_labeled_samples
    samples = load_labeled_samples(str(out))
    assert len(samples) == 3
    assert {s.label for s in samples} == {"benign", "malicious"}


def test_write_manifest_header_row(tmp_path):
    root = _make_dataset(tmp_path)
    pairs = scan_dataset_dir(str(root))
    out = tmp_path / "manifest.csv"
    write_manifest(pairs, str(out))
    with open(out, newline="", encoding="utf-8") as f:
        header = next(csv.reader(f))
    assert header == ["path", "label", "notes"]
