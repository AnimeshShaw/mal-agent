"""Generates the labeled-sample manifest CSV that malagent.evaluation
consumes, by scanning a dataset directory laid out as <root>/benign/*
and <root>/malicious/*. Removes the friction of hand-writing a CSV for
every sample -- point this at a folder, get a manifest."""
from __future__ import annotations
import csv
from pathlib import Path

_LABELS = ("benign", "malicious")


def scan_dataset_dir(root: str) -> list[tuple[str, str]]:
    """Returns (absolute_path, label) pairs for every file directly under
    root/benign and root/malicious (not recursive into further
    subdirectories -- keeps the manifest predictable if someone nests
    extra folders, e.g. an extracted-zip artifact, inside a label dir)."""
    root_path = Path(root)
    pairs: list[tuple[str, str]] = []
    for label in _LABELS:
        subdir = root_path / label
        if not subdir.is_dir():
            continue
        for p in sorted(subdir.iterdir()):
            if p.is_file():
                pairs.append((str(p.resolve()), label))
    if not pairs:
        raise ValueError(
            f"no sample files found under {root_path / 'benign'} or "
            f"{root_path / 'malicious'}")
    return pairs


def write_manifest(pairs: list[tuple[str, str]], out_path: str) -> None:
    with open(out_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["path", "label", "notes"])
        for path, label in pairs:
            writer.writerow([path, label, ""])
