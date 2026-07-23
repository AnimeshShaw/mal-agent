"""IocReputationTool: cross-references IPs/domains already extracted by
StaticFeaturesTool against locally-downloaded threat-intel blocklists
(e.g. ShadowWhisperer/IPs, hagezi/dns-blocklists' Threat Intelligence
Feeds subset). Zero network egress -- purely local file matching, unlike
a VirusTotal-style lookup, which would need an API key, live network
calls, and an EgressPolicy extension. Lists are never bundled into this
repo (separately licensed -- e.g. hagezi is GPL-3.0); same "download
separately, point an env var at it" pattern as CAPA_RULES_PATH/
KNOWN_GOOD_HASHES_PATH."""
from __future__ import annotations
from malagent.contracts import AnalysisState, IOC, Provenance, Sample
from malagent.ioc_reputation import IocReputationTool


def _sample():
    return Sample(sha256="a" * 64, md5="b" * 32, path="/tmp/x.malz",
                  file_type="PE", size=10, provenance=Provenance())


def _state(iocs=None):
    s = AnalysisState(run_id="r1", sample=_sample())
    s.iocs = iocs or []
    return s


def test_skips_when_neither_blocklist_configured(monkeypatch):
    monkeypatch.delenv("IP_BLOCKLIST_PATH", raising=False)
    monkeypatch.delenv("DOMAIN_BLOCKLIST_PATH", raising=False)
    sr = IocReputationTool().run(_state())
    assert sr.status == "skipped"
    assert "not configured" in sr.notes


def test_skips_when_configured_path_does_not_exist(monkeypatch, tmp_path):
    monkeypatch.setenv("IP_BLOCKLIST_PATH", str(tmp_path / "nope.txt"))
    monkeypatch.delenv("DOMAIN_BLOCKLIST_PATH", raising=False)
    sr = IocReputationTool().run(_state())
    assert sr.status == "skipped"


def test_matches_known_bad_ip(monkeypatch, tmp_path):
    ip_file = tmp_path / "ips.txt"
    ip_file.write_text("# comment\n1.2.3.4\n5.6.7.8\n")
    monkeypatch.setenv("IP_BLOCKLIST_PATH", str(ip_file))
    monkeypatch.delenv("DOMAIN_BLOCKLIST_PATH", raising=False)

    state = _state(iocs=[IOC(type="ip", value="1.2.3.4", evidence=["ev1"])])
    sr = IocReputationTool().run(state)
    assert sr.status == "ok"
    assert len(sr.findings) == 1
    assert sr.findings[0].severity == "medium"
    assert "1.2.3.4" in sr.findings[0].claim


def test_no_match_produces_no_findings(monkeypatch, tmp_path):
    ip_file = tmp_path / "ips.txt"
    ip_file.write_text("9.9.9.9\n")
    monkeypatch.setenv("IP_BLOCKLIST_PATH", str(ip_file))
    monkeypatch.delenv("DOMAIN_BLOCKLIST_PATH", raising=False)

    state = _state(iocs=[IOC(type="ip", value="1.2.3.4", evidence=["ev1"])])
    sr = IocReputationTool().run(state)
    assert sr.status == "ok"
    assert sr.findings == []


def test_matches_known_bad_domain_case_insensitive(monkeypatch, tmp_path):
    domain_file = tmp_path / "domains.txt"
    domain_file.write_text("evil.example.top\n")
    monkeypatch.delenv("IP_BLOCKLIST_PATH", raising=False)
    monkeypatch.setenv("DOMAIN_BLOCKLIST_PATH", str(domain_file))

    state = _state(iocs=[IOC(type="domain", value="EVIL.EXAMPLE.TOP", evidence=["ev1"])])
    sr = IocReputationTool().run(state)
    assert sr.status == "ok"
    assert len(sr.findings) == 1


def test_url_ioc_checked_against_domain_blocklist_by_hostname(monkeypatch, tmp_path):
    """URLs are IOCs too (type='url'); the hostname portion should be
    checked against the domain blocklist, not the whole URL string."""
    domain_file = tmp_path / "domains.txt"
    domain_file.write_text("evil.example.top\n")
    monkeypatch.delenv("IP_BLOCKLIST_PATH", raising=False)
    monkeypatch.setenv("DOMAIN_BLOCKLIST_PATH", str(domain_file))

    state = _state(iocs=[IOC(type="url", value="http://evil.example.top/payload.exe",
                             evidence=["ev1"])])
    sr = IocReputationTool().run(state)
    assert sr.status == "ok"
    assert len(sr.findings) == 1


def test_evidence_locator_recognizable_for_corroboration_gate(monkeypatch, tmp_path):
    ip_file = tmp_path / "ips.txt"
    ip_file.write_text("1.2.3.4\n")
    monkeypatch.setenv("IP_BLOCKLIST_PATH", str(ip_file))
    monkeypatch.delenv("DOMAIN_BLOCKLIST_PATH", raising=False)

    state = _state(iocs=[IOC(type="ip", value="1.2.3.4", evidence=["ev1"])])
    sr = IocReputationTool().run(state)
    ev = sr.evidence[0]
    assert ev.locator.startswith("ioc_reputation:")


def test_multiple_matches_each_produce_a_finding(monkeypatch, tmp_path):
    ip_file = tmp_path / "ips.txt"
    ip_file.write_text("1.2.3.4\n5.6.7.8\n")
    monkeypatch.setenv("IP_BLOCKLIST_PATH", str(ip_file))
    monkeypatch.delenv("DOMAIN_BLOCKLIST_PATH", raising=False)

    state = _state(iocs=[IOC(type="ip", value="1.2.3.4", evidence=["ev1"]),
                        IOC(type="ip", value="5.6.7.8", evidence=["ev2"])])
    sr = IocReputationTool().run(state)
    assert len(sr.findings) == 2
