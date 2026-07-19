"""PEHeaderTool should also compute the import-table hash (imphash) --
malware built with the same builder/packer/family typically shares an
identical import table, so imphash is a standard, cheap clustering/lookup
signal (threat-intel platforms and VT track known-bad imphashes). pefile
computes it natively; this was previously unused."""
from __future__ import annotations
import pefile
from malagent.contracts import AnalysisState, Provenance, Sample
from malagent.tools import PEHeaderTool


def _sample():
    return Sample(sha256="a" * 64, md5="b" * 32, path="/tmp/x.malz",
                  file_type="PE", size=10, provenance=Provenance())


def _state():
    return AnalysisState(run_id="r1", sample=_sample())


class _FakePE:
    def __init__(self, path, fast_load=True):
        pass

    def parse_data_directories(self):
        pass

    def get_imphash(self):
        return "aa9e7e1bd35e47c6de05df960241a986"


def test_imphash_recorded_as_hash_ioc(monkeypatch):
    monkeypatch.setattr(pefile, "PE", _FakePE)
    sr = PEHeaderTool().run(_state())
    hash_iocs = [i for i in sr.iocs if i.type == "hash"]
    assert len(hash_iocs) == 1
    assert hash_iocs[0].value == "aa9e7e1bd35e47c6de05df960241a986"


class _FakePENoImphash:
    def __init__(self, path, fast_load=True):
        pass

    def parse_data_directories(self):
        pass

    def get_imphash(self):
        raise Exception("no imports")


def test_imphash_failure_degrades_gracefully_not_error(monkeypatch):
    monkeypatch.setattr(pefile, "PE", _FakePENoImphash)
    sr = PEHeaderTool().run(_state())
    assert sr.status == "ok"
    assert [i for i in sr.iocs if i.type == "hash"] == []


class _FakeSection:
    def __init__(self, name: bytes, entropy: float):
        self.Name = name
        self._entropy = entropy

    def get_entropy(self):
        return self._entropy


class _FakePEWithSections:
    def __init__(self, path, fast_load=True):
        self.sections = [
            _FakeSection(b".text\x00\x00\x00", 5.1),
            _FakeSection(b".data\x00\x00\x00", 7.8),
        ]

    def parse_data_directories(self):
        pass

    def get_imphash(self):
        return None


def test_high_entropy_section_flagged(monkeypatch):
    monkeypatch.setattr(pefile, "PE", _FakePEWithSections)
    sr = PEHeaderTool().run(_state())
    high_entropy = [f for f in sr.findings if "high-entropy section" in f.claim.lower()]
    assert len(high_entropy) == 1
    assert ".data" in high_entropy[0].claim
    assert "7.8" in high_entropy[0].claim


class _FakePENormalEntropy:
    def __init__(self, path, fast_load=True):
        self.sections = [_FakeSection(b".text\x00\x00\x00", 5.1)]

    def parse_data_directories(self):
        pass

    def get_imphash(self):
        return None


def test_normal_entropy_sections_not_flagged(monkeypatch):
    monkeypatch.setattr(pefile, "PE", _FakePENormalEntropy)
    sr = PEHeaderTool().run(_state())
    assert not any("high-entropy section" in f.claim.lower() for f in sr.findings)


class _FakeSectionWithOffsets:
    def __init__(self, name: bytes, ptr: int, size: int):
        self.Name = name
        self.PointerToRawData = ptr
        self.SizeOfRawData = size

    def get_entropy(self):
        return 5.0


class _FakePEForOverlay:
    def __init__(self, path, fast_load=True):
        self.sections = [_FakeSectionWithOffsets(b".text\x00\x00\x00", 0x400, 0x200)]

    def parse_data_directories(self):
        pass

    def get_imphash(self):
        return None


def _state_with_size(size: int) -> AnalysisState:
    sample = Sample(sha256="a" * 64, md5="b" * 32, path="/tmp/x.malz",
                    file_type="PE", size=size, provenance=Provenance())
    return AnalysisState(run_id="r1", sample=sample)


def test_overlay_detected_when_file_larger_than_sections(monkeypatch):
    monkeypatch.setattr(pefile, "PE", _FakePEForOverlay)
    state = _state_with_size(0x400 + 0x200 + 5000)  # 5000 bytes of overlay
    sr = PEHeaderTool().run(state)
    overlay = [f for f in sr.findings if "overlay" in f.claim.lower()]
    assert len(overlay) == 1
    assert "5000" in overlay[0].claim


def test_no_overlay_when_file_size_matches_sections(monkeypatch):
    monkeypatch.setattr(pefile, "PE", _FakePEForOverlay)
    state = _state_with_size(0x400 + 0x200)  # exact match, no overlay
    sr = PEHeaderTool().run(state)
    assert not any("overlay" in f.claim.lower() for f in sr.findings)


def test_small_padding_not_flagged_as_overlay(monkeypatch):
    monkeypatch.setattr(pefile, "PE", _FakePEForOverlay)
    state = _state_with_size(0x400 + 0x200 + 8)  # 8 bytes: normal alignment padding
    sr = PEHeaderTool().run(state)
    assert not any("overlay" in f.claim.lower() for f in sr.findings)
