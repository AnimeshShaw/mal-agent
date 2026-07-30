"""UnpackerTool (ML classifier plan, Phase 2): recursive ZIP/ISO 9660
container unpacking. Motivated by two real samples found in this
project's own dataset while auditing why the deterministic gate abstains
so often: a ZIP wrapping an ISO 9660 image wrapping a real PE payload
(the ISO named to look like a purchase order -- "Ordine di acquisto
(PO_109228)_doc.exe"), and a ZIP bundling a legitimate-looking exe with
several genuine-named Microsoft runtime DLLs plus a couple of oddly
named ones -- a classic DLL-sideloading kit. Neither of these ever
reaches any classifier today because nothing in the pipeline unpacks
containers; StaticFeaturesTool/PEHeaderTool/CapaTool all operate on the
outer container's raw bytes, which don't parse as a PE at all.

ISO-in-ZIP specifically is a documented real evasion technique: ISO
mounting historically didn't propagate the Windows Mark-of-the-Web flag
the way ZIP extraction does, so wrapping a payload in an ISO (itself
delivered via ZIP or email attachment) was a way to dodge SmartScreen.
"""
from __future__ import annotations
import io
import zipfile
from malagent.contracts import AnalysisState, Provenance, Sample
from malagent.unpacker import UnpackerTool

_PLAIN_PE_HEADER = b"MZ" + b"\x00" * 58 + b"\x40\x00\x00\x00"  # e_lfanew stub, not a full parseable PE


def _sample(path):
    return Sample(sha256="a" * 64, md5="b" * 32, path=path, file_type="unknown",
                  size=0, provenance=Provenance())


def _state(path):
    return AnalysisState(run_id="r1", sample=_sample(path))


def _write(tmp_path, name, data):
    p = tmp_path / name
    p.write_bytes(data)
    return str(p)


def _zip_bytes(entries: dict) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for name, data in entries.items():
            zf.writestr(name, data)
    return buf.getvalue()


def test_non_container_sample_is_skipped(tmp_path):
    path = _write(tmp_path, "plain.bin", b"just some ordinary bytes, not a zip or iso")
    sr = UnpackerTool().run(_state(path))
    assert sr.status == "skipped"


def test_zip_containing_plain_file_lists_contents(tmp_path):
    data = _zip_bytes({"readme.txt": b"hello world"})
    path = _write(tmp_path, "sample.zip", data)
    sr = UnpackerTool().run(_state(path))
    assert sr.status == "ok"
    assert any("readme.txt" in e.excerpt for e in sr.evidence)


def test_zip_containing_pe_with_risky_imports_flags_them(monkeypatch, tmp_path):
    """A minimal real PE is hard to construct by hand -- fake pefile.PE
    the same way tests/test_pe_header_tool.py does, so the risky-import
    check inside UnpackerTool is exercised without needing a byte-perfect
    PE file on disk."""
    import malagent.unpacker as unpacker_module

    class _FakePE:
        def __init__(self, data=None, **kw):
            pass

        def parse_data_directories(self):
            pass

        DIRECTORY_ENTRY_IMPORT = [
            type("Entry", (), {"imports": [
                type("Imp", (), {"name": b"CreateRemoteThread"})(),
                type("Imp", (), {"name": b"ReadFile"})(),
            ]})()
        ]

    monkeypatch.setattr(unpacker_module.pefile, "PE", _FakePE)
    zdata = _zip_bytes({"payload.exe": b"MZ" + b"\x00" * 100})
    path = _write(tmp_path, "sample.zip", zdata)
    sr = UnpackerTool().run(_state(path))
    assert sr.status == "ok"
    assert any("CreateRemoteThread" in f.claim for f in sr.findings)
    assert any(f.severity == "medium" for f in sr.findings)


def test_zip_wrapping_iso_wrapping_pe_flags_nested_container_pattern(tmp_path):
    """The exact real shape found in this project's own dataset:
    ZIP -> ISO 9660 -> PE. Live-verified against the real sample
    (dataset/malicious/8e6e963f...) before this test was written --
    pycdlib.open_fp() on the extracted ISO bytes, Joliet path lookup,
    real MZ header recovered. This test uses a real pycdlib-built ISO,
    not a mock, since ISO 9660 structure is too involved to fake
    convincingly and pycdlib is a real, already-added dependency."""
    import pycdlib
    iso_buf = io.BytesIO()
    iso = pycdlib.PyCdlib()
    iso.new(joliet=3)
    payload = b"MZ" + b"\x90" * 100
    iso.add_fp(io.BytesIO(payload), len(payload), "/PAYLOAD.EXE;1",
              joliet_path="/payload.exe")
    iso.write_fp(iso_buf)
    iso.close()

    zdata = _zip_bytes({"invoice.iso": iso_buf.getvalue()})
    path = _write(tmp_path, "sample.zip", zdata)
    sr = UnpackerTool().run(_state(path))
    assert sr.status == "ok"
    assert any("nested" in (f.claim or "").lower() for f in sr.findings)
    assert any(f.severity == "medium" for f in sr.findings)


def test_recursion_depth_guard_stops_and_reports_honestly(tmp_path):
    """Recursively-nested zips (a zip whose only entry is another zip,
    N levels deep) is a classic zip-bomb shape -- must stop at a bound
    and say so, never hang or silently give up with no explanation."""
    inner = _zip_bytes({"leaf.txt": b"x"})
    for _ in range(10):
        inner = _zip_bytes({"nested.zip": inner})
    path = _write(tmp_path, "deep.zip", inner)
    sr = UnpackerTool().run(_state(path))
    assert sr.status in ("ok", "partial")
    assert any("depth" in u.lower() for u in sr.unresolved)


def test_corrupted_zip_magic_but_unparseable_is_error_not_skipped(tmp_path):
    """Distinct from test_non_pe_file_reported_as_skipped_not_error in
    tests/test_pe_header_tool.py: there, the file plainly ISN'T a PE at
    all (wrong format for that tool -- skip). Here, the file DOES claim
    to be a zip (correct magic bytes) but is truncated/corrupted -- this
    is a genuine failure to process something that should have worked,
    so it must stay 'error', not be downgraded to 'skipped'."""
    path = _write(tmp_path, "corrupt.zip", b"PK\x03\x04" + b"\x00" * 10)
    sr = UnpackerTool().run(_state(path))
    assert sr.status == "error"


def test_zip_containing_office_document_not_flagged_as_nested_container(tmp_path):
    """Real bug found via live verification against dataset/malicious/
    fee96a66...: Office Open XML formats (.xlsx/.docx/.pptx) ARE zip
    archives under the hood (confirmed: reading the real .xlsx entry
    from that sample's zip, its first 4 bytes are literally b'PK\\x03\\x04').
    A plain magic-byte zip check recursed into it and raised a false
    'nested container' finding on a completely ordinary spreadsheet
    bundled alongside an executable -- a mundane, extremely common
    pattern (any ZIP that bundles a report + its data), not a suspicious
    one. Office Open XML zips have a recognizable root marker,
    '[Content_Types].xml', that a genuine evasion-shaped nested
    ISO/ZIP-wrapping-an-executable never has."""
    office_zip = _zip_bytes({"[Content_Types].xml": b"<Types/>", "xl/workbook.xml": b"<workbook/>"})
    outer = _zip_bytes({"payload.exe": b"MZ" + b"\x00" * 100, "report.xlsx": office_zip})
    path = _write(tmp_path, "sample.zip", outer)
    sr = UnpackerTool().run(_state(path))
    assert sr.status == "ok"
    assert not any("nested" in (f.claim or "").lower() for f in sr.findings)
    assert any("report.xlsx" in e.excerpt for e in sr.evidence)


def test_missing_pycdlib_degrades_gracefully_for_iso(monkeypatch, tmp_path):
    import malagent.unpacker as unpacker_module
    monkeypatch.setattr(unpacker_module, "pycdlib", None)
    # A minimal real ISO 9660 signature at the standard offset.
    data = bytearray(0x8006)
    data[0x8001:0x8006] = b"CD001"
    path = _write(tmp_path, "sample.iso", bytes(data))
    sr = UnpackerTool().run(_state(path))
    assert sr.status == "skipped"
    assert any("pycdlib" in u.lower() for u in sr.unresolved)
