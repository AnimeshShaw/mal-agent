#!/usr/bin/env python3
"""Collect a diverse, *non-personal* benign corpus for dataset v2.

Every source is a system/application install path or a public corpus --
never a user's Documents/Downloads/Desktop. Files are copied (never
executed) to dataset/benign_v2/<type>/<sha256>.bin and described in
dataset/benign_v2_meta.csv (sha256,file_type,source,origin_path).

Sources, chosen to mirror the malicious file-type mix so that benign
non-PE files finally exist in the evaluation (the 2026-09-27 audit found
none, which is how EMBER's 80% non-PE false-positive rate went unseen):
  pe_exe/pe_dll  Program Files, vendor-stratified (<= 6 files per vendor dir)
  msi            C:\\Windows\\Installer cached installers
  lnk            ProgramData Start Menu shortcuts
  vbs            System32 admin scripts (.vbs/.wsf)
  bat            Program Files .bat/.cmd
  ps1            PowerShell module scripts (.ps1/.psm1/.psd1)
  js             Program Files .js (npm, VS Code, ...)
  zip            pip/conda package archives and .jar
  ooxml          Office templates/add-ins (.dotx/.xltx/.potx/.xlam, incl. benign VBA)
  one            OneNote stationery shipped with Office
  rtf            Program Files .rtf (license texts)
  pdf/doc/xls/ppt  GovDocs1 public corpus (dataset/_sources/govdocs000.zip) + Program Files PDFs
  elf            .so files from manylinux wheels (pip download, never installed)

Usage: python scripts/collect_benign.py [--seed 7]
"""
from __future__ import annotations
import argparse
import csv
import glob
import hashlib
import io
import os
import random
import shutil
import subprocess
import sys
import tempfile
import zipfile
from collections import defaultdict
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
OUT = REPO / "dataset" / "benign_v2"
META = REPO / "dataset" / "benign_v2_meta.csv"
PF = [r"C:\Program Files", r"C:\Program Files (x86)"]
MIN_SIZE, MAX_SIZE = 1_000, 40_000_000
ELF_WHEELS = ["numpy", "pillow", "lxml", "cryptography", "psutil", "pyyaml", "regex",
              "orjson", "zstandard", "markupsafe", "cffi", "msgpack"]


def _glob(patterns):
    out = []
    for pat in patterns:
        out += [f for f in glob.glob(pat, recursive=True) if os.path.isfile(f)]
    return [f for f in out if MIN_SIZE <= os.path.getsize(f) <= MAX_SIZE]


def _vendor_stratified(files, per_vendor, n, rng):
    by_vendor = defaultdict(list)
    for f in files:
        parts = Path(f).parts
        by_vendor[parts[2] if len(parts) > 2 else "?"].append(f)
    picked = []
    for v in sorted(by_vendor):
        rng.shuffle(by_vendor[v])
        picked += by_vendor[v][:per_vendor]
    rng.shuffle(picked)
    return picked[:n]


def _pe_files(ext):
    return _glob([os.path.join(r, "**", f"*.{ext}") for r in PF])


def _govdocs(ext_map, rng):
    zpath = REPO / "dataset" / "_sources" / "govdocs000.zip"
    if not zpath.exists():
        print("  (govdocs000.zip not present -- skipping public-corpus documents)")
        return {}
    by_type = defaultdict(list)
    with zipfile.ZipFile(zpath) as zf:
        names = [n for n in zf.namelist() if not n.endswith("/")]
        rng.shuffle(names)
        for n in names:
            ext = n.rsplit(".", 1)[-1].lower()
            if ext in ext_map and len(by_type[ext]) < ext_map[ext]:
                data = zf.read(n)
                if MIN_SIZE <= len(data) <= MAX_SIZE:
                    by_type[ext].append(("govdocs1:" + n, data))
    return by_type


def _elf_from_wheels(n, rng):
    tmp = Path(tempfile.mkdtemp(prefix="benign_elf_"))
    try:
        for pkg in ELF_WHEELS:
            subprocess.run([sys.executable, "-m", "pip", "download", pkg, "--no-deps",
                            "--only-binary=:all:", "--platform", "manylinux2014_x86_64",
                            "--python-version", "3.11", "-d", str(tmp), "-q"],
                           capture_output=True, timeout=300)
        out = []
        for whl in sorted(tmp.glob("*.whl")):
            with zipfile.ZipFile(whl) as zf:
                for name in zf.namelist():
                    if ".so" in name:
                        data = zf.read(name)
                        if data[:4] == b"\x7fELF" and MIN_SIZE <= len(data) <= MAX_SIZE:
                            out.append((f"wheel:{whl.name}:{name}", data))
        rng.shuffle(out)
        return out[:n]
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--seed", type=int, default=7)
    args = ap.parse_args()
    rng = random.Random(args.seed)

    plan: dict[str, list] = {}  # type -> list of (origin, path_or_bytes)
    plan["pe_exe"] = _vendor_stratified(_pe_files("exe"), 6, 110, rng)
    plan["pe_dll"] = _vendor_stratified(_pe_files("dll"), 3, 50, rng)
    rest = {
        "msi": ([r"C:\Windows\Installer\*.msi"], 30),
        "lnk": ([r"C:\ProgramData\Microsoft\Windows\Start Menu\Programs\**\*.lnk"], 35),
        "vbs": ([r"C:\Windows\System32\*.vbs", r"C:\Windows\System32\*.wsf",
                 r"C:\Windows\System32\Printing_Admin_Scripts\en-US\*.vbs"], 15),
        "bat": ([os.path.join(r, "**", e) for r in PF for e in ("*.bat", "*.cmd")], 25),
        "ps1": ([r"C:\Windows\System32\WindowsPowerShell\v1.0\Modules\**\*.ps*1",
                 r"C:\Program Files\WindowsPowerShell\Modules\**\*.ps*1"], 30),
        "js": ([os.path.join(r, "**", "*.js") for r in PF], 35),
        "zip": ([os.path.expanduser(r"~\miniconda3\pkgs\*.conda"),
                 os.path.join(r"C:\Program Files", "**", "*.jar"),
                 os.path.join(r"C:\Program Files", "**", "*.zip")], 35),
        "ooxml": ([os.path.join(r, "**", e) for r in PF
                   for e in ("*.dotx", "*.xltx", "*.potx", "*.xlam", "*.docx", "*.xlsx")], 40),
        "one": ([os.path.join(r, "**", "*.one") for r in PF], 10),
        "rtf": ([os.path.join(r, "**", "*.rtf") for r in PF], 20),
        "pdf": ([os.path.join(r, "**", "*.pdf") for r in PF], 15),
    }
    for t, (pats, n) in rest.items():
        files = _glob(pats)
        rng.shuffle(files)
        plan[t] = files[:n]

    gov = _govdocs({"pdf": 40, "doc": 30, "xls": 30, "ppt": 15}, rng)
    for ext, items in gov.items():
        plan.setdefault(ext, [])
        plan[ext] += items
    plan["elf"] = _elf_from_wheels(30, rng)

    OUT.mkdir(parents=True, exist_ok=True)
    seen: set[str] = set()
    rows = []
    for t, items in plan.items():
        d = OUT / t
        d.mkdir(exist_ok=True)
        for item in items:
            if isinstance(item, tuple):
                origin, data = item
            else:
                origin = item
                try:
                    data = Path(item).read_bytes()
                except OSError:
                    continue
            h = hashlib.sha256(data).hexdigest()
            if h in seen:
                continue
            seen.add(h)
            (d / f"{h}.bin").write_bytes(data)
            source = origin.split(":", 1)[0] if origin.startswith(("govdocs1:", "wheel:")) else "system"
            rows.append([h, t, source, origin])
        print(f"{t:8s} {sum(1 for r in rows if r[1] == t)}")
    with open(META, "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["sha256", "file_type", "source", "origin_path"])
        w.writerows(rows)
    print(f"total {len(rows)} -> {OUT}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
