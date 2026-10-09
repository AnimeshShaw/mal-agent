"""VirusTotal hash lookup. Needs a real
API key (VIRUSTOTAL_API_KEY) and EgressPolicy.allow_hash_lookup=True --
neither is available in this session (no key was provided), so this is
NOT live-verified against the real VirusTotal API, same honest
limitation as DieTool. Tested via mocked HTTP responses matching VT's
documented v3 API response shape."""
from __future__ import annotations
from malagent.contracts import AnalysisState, EgressPolicy, Provenance, Sample
from malagent.virustotal_tool import VirusTotalTool


def _sample():
    return Sample(sha256="a" * 64, md5="b" * 32, path="/tmp/x.malz",
                  file_type="PE", size=10, provenance=Provenance())


def _state(policy=None):
    return AnalysisState(run_id="r1", sample=_sample(), policy=policy or EgressPolicy())


class _FakeResponse:
    def __init__(self, status_code, json_data=None):
        self.status_code = status_code
        self._json = json_data or {}

    def json(self):
        return self._json


def _vt_response(malicious=0, suspicious=0, harmless=60, undetected=5):
    return {"data": {"attributes": {"last_analysis_stats": {
        "malicious": malicious, "suspicious": suspicious,
        "harmless": harmless, "undetected": undetected,
    }}}}


def test_skips_when_no_api_key(monkeypatch):
    monkeypatch.delenv("VIRUSTOTAL_API_KEY", raising=False)
    sr = VirusTotalTool().run(_state())
    assert sr.status == "skipped"
    assert "VIRUSTOTAL_API_KEY" in sr.unresolved[0]


def test_skips_when_egress_policy_blocks_hash_lookup(monkeypatch):
    monkeypatch.setenv("VIRUSTOTAL_API_KEY", "fake-key")
    policy = EgressPolicy(allow_cloud=True, allow_hash_lookup=False)
    sr = VirusTotalTool().run(_state(policy=policy))
    assert sr.status == "skipped"
    assert any("policy" in u.lower() for u in sr.unresolved)


def test_skips_when_cloud_disabled_even_with_hash_lookup_opted_in(monkeypatch):
    monkeypatch.setenv("VIRUSTOTAL_API_KEY", "fake-key")
    policy = EgressPolicy(allow_cloud=False, allow_hash_lookup=True)
    sr = VirusTotalTool().run(_state(policy=policy))
    assert sr.status == "skipped"


def test_high_detection_count_produces_high_severity_finding(monkeypatch):
    monkeypatch.setenv("VIRUSTOTAL_API_KEY", "fake-key")
    policy = EgressPolicy(allow_cloud=True, allow_hash_lookup=True)

    def fake_get(url, headers=None, timeout=None):
        return _FakeResponse(200, _vt_response(malicious=45))

    monkeypatch.setattr("malagent.virustotal_tool.requests.get", fake_get)
    sr = VirusTotalTool().run(_state(policy=policy))
    assert sr.status == "ok"
    assert len(sr.findings) == 1
    assert sr.findings[0].severity == "high"
    assert "45" in sr.findings[0].claim


def test_low_detection_count_produces_medium_severity_finding(monkeypatch):
    monkeypatch.setenv("VIRUSTOTAL_API_KEY", "fake-key")
    policy = EgressPolicy(allow_cloud=True, allow_hash_lookup=True)

    def fake_get(url, headers=None, timeout=None):
        return _FakeResponse(200, _vt_response(malicious=2))

    monkeypatch.setattr("malagent.virustotal_tool.requests.get", fake_get)
    sr = VirusTotalTool().run(_state(policy=policy))
    assert sr.findings[0].severity == "medium"


def test_zero_detections_produces_no_findings(monkeypatch):
    monkeypatch.setenv("VIRUSTOTAL_API_KEY", "fake-key")
    policy = EgressPolicy(allow_cloud=True, allow_hash_lookup=True)

    def fake_get(url, headers=None, timeout=None):
        return _FakeResponse(200, _vt_response(malicious=0, suspicious=0))

    monkeypatch.setattr("malagent.virustotal_tool.requests.get", fake_get)
    sr = VirusTotalTool().run(_state(policy=policy))
    assert sr.status == "ok"
    assert sr.findings == []


def test_hash_not_found_reports_honestly_not_as_benign(monkeypatch):
    """A 404 means VT has never seen this hash -- honest 'unknown', never
    silently treated as evidence of benignity (a genuinely novel malware
    sample would also 404 on first submission)."""
    monkeypatch.setenv("VIRUSTOTAL_API_KEY", "fake-key")
    policy = EgressPolicy(allow_cloud=True, allow_hash_lookup=True)

    def fake_get(url, headers=None, timeout=None):
        return _FakeResponse(404)

    monkeypatch.setattr("malagent.virustotal_tool.requests.get", fake_get)
    sr = VirusTotalTool().run(_state(policy=policy))
    assert sr.status == "ok"
    assert sr.findings == []
    assert any("not present" in u.lower() or "not found" in u.lower() for u in sr.unresolved)


def test_http_error_reports_error_not_crash(monkeypatch):
    monkeypatch.setenv("VIRUSTOTAL_API_KEY", "fake-key")
    policy = EgressPolicy(allow_cloud=True, allow_hash_lookup=True)

    def fake_get(url, headers=None, timeout=None):
        return _FakeResponse(500)

    monkeypatch.setattr("malagent.virustotal_tool.requests.get", fake_get)
    sr = VirusTotalTool().run(_state(policy=policy))
    assert sr.status == "error"


def test_network_exception_reports_error_not_crash(monkeypatch):
    monkeypatch.setenv("VIRUSTOTAL_API_KEY", "fake-key")
    policy = EgressPolicy(allow_cloud=True, allow_hash_lookup=True)

    def fake_get(url, headers=None, timeout=None):
        raise ConnectionError("network unreachable")

    monkeypatch.setattr("malagent.virustotal_tool.requests.get", fake_get)
    sr = VirusTotalTool().run(_state(policy=policy))
    assert sr.status == "error"


def test_api_key_never_appears_in_findings_or_notes(monkeypatch):
    monkeypatch.setenv("VIRUSTOTAL_API_KEY", "super-secret-key-12345")
    policy = EgressPolicy(allow_cloud=True, allow_hash_lookup=True)

    def fake_get(url, headers=None, timeout=None):
        return _FakeResponse(200, _vt_response(malicious=10))

    monkeypatch.setattr("malagent.virustotal_tool.requests.get", fake_get)
    sr = VirusTotalTool().run(_state(policy=policy))
    dump = str(sr.findings) + str(sr.notes) + str(sr.unresolved)
    assert "super-secret-key-12345" not in dump
