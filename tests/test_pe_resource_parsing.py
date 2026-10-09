"""PE resource (.rsrc) parsing: a common way to hide
a payload is to embed it as a PE resource -- either a full second PE
(dropper/loader pattern) or a high-entropy (packed/encrypted) blob. Neither
signal existed before; PEHeaderTool only looked at imports/sections/overlay/
rich-header, never walked DIRECTORY_ENTRY_RESOURCE at all."""
from __future__ import annotations
import pefile
from malagent.contracts import AnalysisState, Provenance, Sample
from malagent.tools import PEHeaderTool


def _sample():
    return Sample(sha256="a" * 64, md5="b" * 32, path="/tmp/x.malz",
                  file_type="PE", size=10, provenance=Provenance())


def _state():
    return AnalysisState(run_id="r1", sample=_sample())


class _Leaf:
    """A single leaf resource entry (language level) -- pefile exposes the
    RVA/size via .data.struct, and the actual bytes via pe.get_data()."""
    def __init__(self, rva, size):
        class _Struct:
            OffsetToData = rva
            Size = size
        class _Data:
            struct = _Struct()
        self.data = _Data()


class _NameEntry:
    def __init__(self, leaves):
        class _Dir:
            entries = leaves
        self.directory = _Dir()


class _TypeEntry:
    def __init__(self, name_entries):
        class _Dir:
            entries = name_entries
        self.directory = _Dir()


def _resource_tree(blob_by_rva):
    """Builds a minimal 3-level pefile resource tree (type -> name -> lang)
    where each (rva, blob) pair becomes one leaf resource at that RVA."""
    name_entries = []
    for rva, blob in blob_by_rva.items():
        leaf = _Leaf(rva=rva, size=len(blob))
        name_entries.append(_NameEntry([leaf]))
    return [_TypeEntry(name_entries)]


class _FakePEBase:
    def __init__(self, path, fast_load=True):
        self.sections = []

    def parse_data_directories(self):
        pass

    def get_imphash(self):
        return None

    def parse_rich_header(self):
        return None


def _fake_pe_with_resources(blob_by_rva):
    class _FakePE(_FakePEBase):
        def __init__(self, path, fast_load=True):
            super().__init__(path, fast_load)
            self.DIRECTORY_ENTRY_RESOURCE = type(
                "R", (), {"entries": _resource_tree(blob_by_rva)})()

        def get_data(self, rva, length):
            return blob_by_rva[rva]

    return _FakePE


def test_embedded_pe_in_resource_flagged():
    embedded = b"MZ" + b"\x90" * 62 + b"embedded PE payload"
    fake = _fake_pe_with_resources({0x1000: embedded})
    import pefile as pefile_mod
    orig = pefile_mod.PE
    pefile_mod.PE = fake
    try:
        sr = PEHeaderTool().run(_state())
    finally:
        pefile_mod.PE = orig
    assert any("embedded PE" in f.claim for f in sr.findings)
    assert any(f.severity in ("high", "medium") for f in sr.findings if "embedded PE" in f.claim)


def test_high_entropy_resource_blob_flagged():
    import os
    high_entropy_blob = os.urandom(512)  # random bytes ~= max entropy
    fake = _fake_pe_with_resources({0x2000: high_entropy_blob})
    import pefile as pefile_mod
    orig = pefile_mod.PE
    pefile_mod.PE = fake
    try:
        sr = PEHeaderTool().run(_state())
    finally:
        pefile_mod.PE = orig
    assert any("high-entropy" in f.claim.lower() and "resource" in f.claim.lower()
              for f in sr.findings)


def test_normal_resource_blob_not_flagged():
    normal_blob = b"A" * 512  # zero entropy, not a PE
    fake = _fake_pe_with_resources({0x3000: normal_blob})
    import pefile as pefile_mod
    orig = pefile_mod.PE
    pefile_mod.PE = fake
    try:
        sr = PEHeaderTool().run(_state())
    finally:
        pefile_mod.PE = orig
    assert not any("embedded PE" in f.claim or "resource" in f.claim.lower() for f in sr.findings)


def test_no_resource_directory_does_not_error():
    class _FakePE(_FakePEBase):
        pass
    import pefile as pefile_mod
    orig = pefile_mod.PE
    pefile_mod.PE = _FakePE
    try:
        sr = PEHeaderTool().run(_state())
    finally:
        pefile_mod.PE = orig
    assert sr.status == "ok"


def test_png_icon_resource_not_flagged_as_high_entropy():
    """Real false positive, found live on notepad.exe/explorer.exe: modern
    Windows icons (Vista+) embed PNG images for larger icon sizes, and PNG
    is internally compressed -- entropy ~7.9-8.0, indistinguishable from a
    packed/encrypted blob by entropy alone. Confirmed the exact bytes
    pefile returns for a real notepad.exe resource start with the literal
    PNG magic header. This is an innocent, structurally-identifiable
    explanation for high entropy, not a packing signal."""
    import os
    import zlib
    # a real, valid minimal PNG: signature + IHDR + IDAT (zlib-compressed) + IEND
    sig = b"\x89PNG\r\n\x1a\n"
    ihdr_data = (1).to_bytes(4, "big") + (1).to_bytes(4, "big") + bytes([8, 6, 0, 0, 0])
    def chunk(tag, data):
        import struct
        c = tag + data
        return struct.pack(">I", len(data)) + c + struct.pack(">I", zlib.crc32(c))
    idat_data = zlib.compress(b"\x00\xff\xff\xff\xff")
    png = sig + chunk(b"IHDR", ihdr_data) + chunk(b"IDAT", idat_data) + chunk(b"IEND", b"")
    padded = png + os.urandom(512)  # pad past the size floor, still PNG-prefixed
    fake = _fake_pe_with_resources({0x5000: padded})
    import pefile as pefile_mod
    orig = pefile_mod.PE
    pefile_mod.PE = fake
    try:
        sr = PEHeaderTool().run(_state())
    finally:
        pefile_mod.PE = orig
    assert not any("high-entropy" in f.claim.lower() for f in sr.findings)


def test_small_resource_blobs_not_flagged_as_high_entropy():
    """Tiny resources (icons, version info fragments) shouldn't trigger
    entropy-based suspicion -- only worth flagging above a size floor
    where high entropy is actually meaningful."""
    import os
    tiny_blob = os.urandom(8)
    fake = _fake_pe_with_resources({0x4000: tiny_blob})
    import pefile as pefile_mod
    orig = pefile_mod.PE
    pefile_mod.PE = fake
    try:
        sr = PEHeaderTool().run(_state())
    finally:
        pefile_mod.PE = orig
    assert not any("high-entropy" in f.claim.lower() for f in sr.findings)
