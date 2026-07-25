"""Wide/Unicode (UTF-16LE) string extraction -- Windows PEs routinely carry
these, and the existing ASCII-only extractor misses them entirely."""
from __future__ import annotations
from malagent.contracts import AnalysisState, Provenance, Sample
from malagent.tools import StaticFeaturesTool


def _state_for(tmp_path, data: bytes) -> AnalysisState:
    p = tmp_path / "sample.bin"
    p.write_bytes(data)
    sample = Sample(sha256="a" * 64, md5="b" * 32, path=str(p),
                    file_type="PE", size=len(data), provenance=Provenance())
    return AnalysisState(run_id="r1", sample=sample)


def test_wide_string_suspicious_marker_detected(tmp_path):
    data = b"MZ" + b"\x00" * 62 + "cmd.exe".encode("utf-16-le") + b"\x00" * 32
    sr = StaticFeaturesTool().run(_state_for(tmp_path, data))
    wide = [f for f in sr.findings if f.claim.startswith("Suspicious wide")]
    assert len(wide) == 1
    assert "cmd.exe" in wide[0].claim


def test_wide_string_finding_has_correct_locator(tmp_path):
    data = b"MZ" + b"\x00" * 62 + "WinExec".encode("utf-16-le") + b"\x00" * 32
    sr = StaticFeaturesTool().run(_state_for(tmp_path, data))
    wide_ev = [e for e in sr.evidence if e.locator == "widestring:WinExec"]
    assert len(wide_ev) == 1


def test_no_wide_strings_present_produces_no_wide_findings(tmp_path):
    data = b"MZ" + b"\x00" * 126
    sr = StaticFeaturesTool().run(_state_for(tmp_path, data))
    assert not any(f.claim.startswith("Suspicious wide") for f in sr.findings)


def test_dotnet_namespace_string_not_extracted_as_domain_ioc(tmp_path):
    """.NET assemblies routinely embed PascalCase namespace strings
    (System.Net, System.IO, System.Text.Json, ...) as ordinary metadata --
    every segment capitalized, per C# convention. The domain regex's TLD
    list includes 'net'/'io', so these were being misextracted as domain
    IOCs. Live-verified this is a real false-positive risk: 'System.Net'
    happens to collide with an actual entry in a real threat-intel domain
    blocklist (hagezi), which IocReputationTool then scored as a match --
    a coincidental string collision, not real evidence of C2 traffic."""
    data = b"MZ" + b"\x00" * 60 + b"System.Net" + b"\x00" * 60
    sr = StaticFeaturesTool().run(_state_for(tmp_path, data))
    assert not any(i.type == "domain" and i.value == "System.Net" for i in sr.iocs)


def test_lowercase_domain_matching_a_namespace_word_still_extracted(tmp_path):
    """The fix must not blanket-exclude real domains that happen to share
    a name with a common namespace word -- 'system.net' in all-lowercase
    is exactly how a real malicious domain would appear in a malware
    config string, and IS a real entry in the hagezi blocklist."""
    data = b"MZ" + b"\x00" * 60 + b"system.net" + b"\x00" * 60
    sr = StaticFeaturesTool().run(_state_for(tmp_path, data))
    assert any(i.type == "domain" and i.value == "system.net" for i in sr.iocs)


def test_real_looking_domain_still_extracted(tmp_path):
    data = b"MZ" + b"\x00" * 60 + b"evil-c2-panel.top" + b"\x00" * 60
    sr = StaticFeaturesTool().run(_state_for(tmp_path, data))
    assert any(i.type == "domain" and i.value == "evil-c2-panel.top" for i in sr.iocs)
