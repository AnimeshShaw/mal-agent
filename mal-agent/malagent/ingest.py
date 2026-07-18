"""Sample ingest + defang + provenance (D10/D13). Computes identity hashes,
copies into a quarantine dir with a neutral extension (never auto-executable),
and records chain-of-custody."""
from __future__ import annotations
import hashlib
import os
import shutil
import uuid
from pathlib import Path
from typing import Optional
from .contracts import Provenance, Sample


def _detect_type(data: bytes) -> str:
    if data[:2] == b"MZ":
        return "PE"
    if data[:4] == b"\x7fELF":
        return "ELF"
    if data[:4] in (b"\xfe\xed\xfa\xce", b"\xcf\xfa\xed\xfe"):
        return "Mach-O"
    return "unknown"


def ingest(path: str, quarantine: str = "./quarantine",
           provenance: Optional[Provenance] = None) -> Sample:
    src = Path(path)
    data = src.read_bytes()
    sha256 = hashlib.sha256(data).hexdigest()
    md5 = hashlib.md5(data).hexdigest()
    Path(quarantine).mkdir(parents=True, exist_ok=True)
    dst = Path(quarantine) / f"{sha256}.malz"      # defanged extension
    if not dst.exists():
        shutil.copy2(src, dst)
        os.chmod(dst, 0o400)                        # read-only, not executable
    return Sample(sha256=sha256, md5=md5, path=str(dst), file_type=_detect_type(data),
                  size=len(data), provenance=provenance or Provenance())


def new_run_id() -> str:
    return uuid.uuid4().hex
