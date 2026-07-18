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
