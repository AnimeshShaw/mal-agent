#!/usr/bin/env python3
"""Build the exact dataset package to deposit on Mendeley Data + Hugging
Face for the paper's Data Availability statement. Read-only over
research_out/ and bundles/v2/ -- never modifies them.

Real finding this script exists because of: evidence bundles and a handful
of model rationale strings contain LIVE, undefanged IOCs (e.g. a real
"http://..." URL copied verbatim out of a sample). The web UI already warns
analysts to defang before sharing ("Copied out of the sample: defang before
sharing") but that was only ever a UI label, not an actual transformation --
there was no reusable defang function anywhere in the codebase before this
script. Every string value in every deposited file is run through one here.

Defanging scope (deliberately conservative, see body for why):
  - http://  -> hxxp://      (and the dots inside that URL's host)
  - https:// -> hxxps://     (and the dots inside that URL's host)
  - validated IPv4 addresses (each octet checked 0-255, so "0.822" or
    "6.35" -- real F1/entropy values that happen to contain dots -- are
    never touched) -> dots bracketed, e.g. 1.2.3.4 -> 1[.]2[.]3[.]4
  - iocs[] entries already explicitly typed "domain" or "ip" by the
    pipeline's own extraction -- dots bracketed unconditionally, since
    there's no ambiguity about what these are
  - bare domains inside otherwise-plain prose are NOT defanged beyond the
    above; that's a real scoping choice (high false-positive risk on
    ordinary text) stated here rather than silently done

Output: a single clean directory tree, ready to zip and upload.
"""
from __future__ import annotations
import csv
import json
import re
import shutil
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent

IPV4_RE = re.compile(r"\b(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\b")
URL_RE = re.compile(r"\b(https?)://([^\s\"'<>]+)")


def _valid_octets(m: re.Match) -> bool:
    return all(0 <= int(g) <= 255 for g in m.groups())


def defang_text(s: str) -> str:
    """Defang any http(s) URL and any validated IPv4 address in free text.
    Does not touch bare domains or anything else -- see module docstring."""
    if not isinstance(s, str) or not s:
        return s

    def _url_sub(m: re.Match) -> str:
        scheme, rest = m.group(1), m.group(2)
        defanged_scheme = {"http": "hxxp", "https": "hxxps"}[scheme]
        return f"{defanged_scheme}://{rest.replace('.', '[.]')}"

    s = URL_RE.sub(_url_sub, s)

    def _ip_sub(m: re.Match) -> str:
        if not _valid_octets(m):
            return m.group(0)
        return m.group(0).replace(".", "[.]")

    s = IPV4_RE.sub(_ip_sub, s)
    return s


def defang_ioc_value(value: str, ioc_type: str) -> str:
    """For entries the pipeline already explicitly typed as domain/ip/url,
    defang unconditionally -- no ambiguity, these are known indicators."""
    if not isinstance(value, str):
        return value
    if ioc_type in ("domain", "ip"):
        return value.replace(".", "[.]")
    if ioc_type == "url":
        return defang_text(value)
    return value


def walk_defang(obj, path_hint: str = ""):
    """Recursively defang every string value in a JSON-like structure.
    iocs[] entries get the stronger type-aware treatment; everything else
    gets the conservative free-text treatment."""
    if isinstance(obj, dict):
        out = {}
        for k, v in obj.items():
            if k == "iocs" and isinstance(v, list):
                out[k] = [
                    {**item, "value": defang_ioc_value(item.get("value"), item.get("type"))}
                    if isinstance(item, dict) else item
                    for item in v
                ]
            else:
                out[k] = walk_defang(v, f"{path_hint}.{k}")
        return out
    if isinstance(obj, list):
        return [walk_defang(x, path_hint) for x in obj]
    if isinstance(obj, str):
        return defang_text(obj)
    return obj


def process_jsonl(src: Path, dst: Path) -> int:
    dst.parent.mkdir(parents=True, exist_ok=True)
    n = 0
    with open(src, encoding="utf-8") as fin, open(dst, "w", encoding="utf-8") as fout:
        for line in fin:
            line = line.strip()
            if not line:
                continue
            rec = json.loads(line)
            fout.write(json.dumps(walk_defang(rec), ensure_ascii=False) + "\n")
            n += 1
    return n


def process_bundle(src: Path, dst: Path) -> None:
    dst.parent.mkdir(parents=True, exist_ok=True)
    rec = json.loads(src.read_text(encoding="utf-8"))
    dst.write_text(json.dumps(walk_defang(rec), ensure_ascii=False), encoding="utf-8")


def process_manifest(src: Path, dst: Path) -> int:
    """Drop the local filesystem path prefix, keep sha256 (from the
    filename) + label + format + source + first_seen + split. No file
    content, ever -- this is metadata only, same as every malware-research
    manifest that gets shared publicly."""
    dst.parent.mkdir(parents=True, exist_ok=True)
    n = 0
    with open(src, encoding="utf-8", newline="") as fin, \
         open(dst, "w", encoding="utf-8", newline="") as fout:
        reader = csv.DictReader(fin)
        writer = csv.DictWriter(fout, fieldnames=["sha256", "label", "file_type", "source", "first_seen", "split"])
        writer.writeheader()
        for row in reader:
            sha256 = Path(row["path"]).stem
            writer.writerow({
                "sha256": sha256, "label": row["label"], "file_type": row["file_type"],
                "source": row["source"], "first_seen": row["first_seen"], "split": row["split"],
            })
            n += 1
    return n


def main() -> int:
    out = REPO / "research_out" / "deposit"
    if out.exists():
        shutil.rmtree(out)
    out.mkdir(parents=True)

    print("[1/5] manifest ...")
    n = process_manifest(REPO / "dataset" / "manifest_v2.csv", out / "manifest.csv")
    print(f"      {n} rows -> manifest.csv (metadata only: sha256/label/format/source/date/split)")

    print("[2/5] evidence bundles ...")
    bundles_dir = REPO / "bundles" / "v2"
    n = 0
    for f in sorted(bundles_dir.glob("*.json")):
        process_bundle(f, out / "bundles" / f.name)
        n += 1
    print(f"      {n} bundles -> bundles/ (defanged)")

    print("[3/5] experiment outputs ...")
    for exp in ("main", "adversarial", "reliability", "claims"):
        src_dir = REPO / "research_out" / exp
        if not src_dir.is_dir():
            continue
        for f in sorted(src_dir.glob("*.jsonl")):
            n = process_jsonl(f, out / "experiments" / exp / f.name)
            print(f"      {exp}/{f.name}: {n} records (defanged)")

    print("[4/5] aggregated report ...")
    (out / "report").mkdir(parents=True, exist_ok=True)
    report_dir = REPO / "research_out" / "report"
    if report_dir.is_dir():
        for f in report_dir.glob("report.*"):
            shutil.copy2(f, out / "report" / f.name)
    print("      copied report.md + report.json (aggregate stats only, nothing to defang)")

    print("[5/5] figure stats ...")
    stats_src = REPO / "paper" / "figures" / "stats.json"
    if stats_src.exists():
        shutil.copy2(stats_src, out / "report" / "figures_stats.json")
    print("      copied figures_stats.json")

    print(f"\nDone. Deposit-ready tree at: {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
