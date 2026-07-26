"""Family-attribution heuristic + macro-F1 scoring (M6).

Ground truth for dataset/malicious/ samples cannot be reconstructed from
which --tags query fetched them (scripts/fetch_malwarebazaar.py never
persisted that), so it is fetched fresh, honestly, from MalwareBazaar's own
get_info API per hash (scripts/fetch_family_ground_truth.py) -- see
dataset/family_ground_truth.csv.

Two real signals are combined here:
  1. capa's own 'malware-family' namespace rules. Checked against the real
     capa-rules-9.4.0 corpus: this namespace only contains donut-loader and
     plugx rules -- confirmed empirically to NEVER fire against real fetched
     samples from this project's family set (AgentTesla, RedLineStealer,
     Emotet, Lokibot, Formbook, Remcos, AsyncRAT, njRAT; live capa run
     against a real AsyncRAT .NET sample matched 52 rules, zero of them
     malware-family). The extraction logic is still implemented and tested
     here since it is a real signal capa itself provides and costs nothing
     to check when present.
  2. imphash nearest-neighbor: samples built by the same builder/packer
     often share an identical import table. Evaluated via LEAVE-ONE-OUT
     against this project's own fetched dataset (no external imphash-to-family
     reference database exists here) -- this measures whether the dataset's
     own imphash clusters agree with MalwareBazaar's real labels, not
     real-world generalization to samples built with a different imphash.

Mocking conventions follow test_pe_header_tool.py (fake pefile.PE) and
test_capa_tool.py (fake capa rules dict via monkeypatched subprocess.run)."""
from __future__ import annotations
import json as _json
from pathlib import Path
import pefile
from malagent.family_attribution import (
    FamilyAttribution,
    attribute_family,
    compute_capa_family_hits,
    compute_imphash,
    compute_macro_f1,
    extract_capa_malware_family_hits,
    load_family_ground_truth,
    predict_all_leave_one_out,
    predict_family_by_imphash,
    run_family_attribution,
)


# ---------- capa malware-family namespace extraction ----------

def test_extract_capa_malware_family_hits_returns_family_names():
    doc = {"rules": {
        "match known plugx module": {"meta": {"namespace": "malware-family/plugx"}},
        "load shellcode via donut": {"meta": {"namespace": "malware-family/donut-loader"}},
    }}
    hits = extract_capa_malware_family_hits(doc)
    assert sorted(hits) == ["donut-loader", "plugx"]


def test_extract_capa_malware_family_hits_ignores_other_namespaces():
    doc = {"rules": {
        "read file on Windows": {"meta": {"namespace": "host-interaction/file-system/read"}},
    }}
    assert extract_capa_malware_family_hits(doc) == []


def test_extract_capa_malware_family_hits_handles_missing_namespace():
    doc = {"rules": {"some rule": {"meta": {}}}}
    assert extract_capa_malware_family_hits(doc) == []


def test_extract_capa_malware_family_hits_handles_empty_or_none_doc():
    assert extract_capa_malware_family_hits({}) == []
    assert extract_capa_malware_family_hits(None) == []


# ---------- real capa invocation for the malware-family signal ----------

def _fake_capa_run(rules: dict):
    class _Result:
        stdout = _json.dumps({"rules": rules}).encode()

    def run(*a, **kw):
        return _Result()
    return run


def test_compute_capa_family_hits_returns_hits(monkeypatch):
    rules = {"match known plugx module": {"meta": {"namespace": "malware-family/plugx"}}}
    monkeypatch.setattr("shutil.which", lambda name: "/usr/bin/capa")
    monkeypatch.setattr("subprocess.run", _fake_capa_run(rules))
    assert compute_capa_family_hits("/tmp/x.bin", size=1024) == ["plugx"]


def test_compute_capa_family_hits_returns_empty_when_capa_not_installed(monkeypatch):
    monkeypatch.setattr("shutil.which", lambda name: None)
    assert compute_capa_family_hits("/tmp/x.bin", size=1024) == []


def test_compute_capa_family_hits_returns_empty_over_size_cap(monkeypatch):
    called = []
    monkeypatch.setattr("shutil.which", lambda name: "/usr/bin/capa")
    monkeypatch.setattr("subprocess.run", lambda *a, **kw: called.append(1))
    from malagent.tools import _CAPA_MAX_SIZE_BYTES
    assert compute_capa_family_hits("/tmp/x.bin", size=_CAPA_MAX_SIZE_BYTES + 1) == []
    assert called == []


def test_compute_capa_family_hits_degrades_gracefully_on_failure(monkeypatch):
    monkeypatch.setattr("shutil.which", lambda name: "/usr/bin/capa")

    def _raise(*a, **kw):
        raise Exception("capa crashed")
    monkeypatch.setattr("subprocess.run", _raise)
    assert compute_capa_family_hits("/tmp/x.bin", size=1024) == []


# ---------- imphash ----------

class _FakePE:
    def __init__(self, path, fast_load=True):
        self.parsed_data_directories = False

    def parse_data_directories(self):
        self.parsed_data_directories = True

    def get_imphash(self):
        return "deadbeefdeadbeefdeadbeefdeadbeef"


def test_compute_imphash_returns_hash(monkeypatch):
    monkeypatch.setattr(pefile, "PE", _FakePE)
    assert compute_imphash("/tmp/x.bin") == "deadbeefdeadbeefdeadbeefdeadbeef"


class _FakePENoParseCall:
    """Real pefile (confirmed live against a real .NET malware sample in
    dataset/malicious/) returns an EMPTY string, not an exception, from
    get_imphash() under fast_load=True unless parse_data_directories() is
    called first -- fast_load skips import-table parsing entirely, same
    gotcha PEHeaderTool (malagent/tools.py) already has to work around."""
    last_instance = None

    def __init__(self, path, fast_load=True):
        self.parsed = False
        _FakePENoParseCall.last_instance = self

    def parse_data_directories(self):
        self.parsed = True

    def get_imphash(self):
        return "aa9e7e1bd35e47c6de05df960241a986" if self.parsed else ""


def test_compute_imphash_calls_parse_data_directories_before_get_imphash(monkeypatch):
    """Regression: without parse_data_directories(), get_imphash() silently
    returns '' under fast_load -- live-verified against a real dataset
    sample, not a hypothetical. Missing this call turned every real
    imphash into None, collapsing the whole leave-one-out heuristic."""
    monkeypatch.setattr(pefile, "PE", _FakePENoParseCall)
    assert compute_imphash("/tmp/x.bin") == "aa9e7e1bd35e47c6de05df960241a986"


class _FakePEFails:
    def __init__(self, path, fast_load=True):
        raise Exception("not a PE")


def test_compute_imphash_degrades_gracefully_on_non_pe(monkeypatch):
    monkeypatch.setattr(pefile, "PE", _FakePEFails)
    assert compute_imphash("/tmp/x.bin") is None


class _FakePENoImphash:
    def __init__(self, path, fast_load=True):
        pass

    def get_imphash(self):
        raise Exception("no imports")


def test_compute_imphash_returns_none_when_pefile_raises_on_get_imphash(monkeypatch):
    monkeypatch.setattr(pefile, "PE", _FakePENoImphash)
    assert compute_imphash("/tmp/x.bin") is None


class _FakePEEmptyImphash:
    def __init__(self, path, fast_load=True):
        pass

    def get_imphash(self):
        return ""


def test_compute_imphash_treats_empty_string_as_none(monkeypatch):
    monkeypatch.setattr(pefile, "PE", _FakePEEmptyImphash)
    assert compute_imphash("/tmp/x.bin") is None


# ---------- imphash-based nearest-neighbor prediction (leave-one-out) ----------

def test_predict_family_by_imphash_majority_vote():
    imphash_by_hash = {"a": "H1", "b": "H1", "c": "H1", "target": "H1"}
    family_by_hash = {"a": "AgentTesla", "b": "AgentTesla", "c": "RedLineStealer"}
    result = predict_family_by_imphash("target", "H1", imphash_by_hash, family_by_hash)
    assert result == "AgentTesla"


def test_predict_family_by_imphash_excludes_target_itself():
    """The target's own (hash, family) pair must never be counted as its
    own neighbor -- a labeled sample trivially 'predicting' itself is not a
    real signal."""
    imphash_by_hash = {"target": "H1"}
    family_by_hash = {"target": "AgentTesla"}
    assert predict_family_by_imphash("target", "H1", imphash_by_hash, family_by_hash) is None


def test_predict_family_by_imphash_no_shared_imphash_returns_none():
    imphash_by_hash = {"a": "H1", "target": "H2"}
    family_by_hash = {"a": "AgentTesla"}
    assert predict_family_by_imphash("target", "H2", imphash_by_hash, family_by_hash) is None


def test_predict_family_by_imphash_none_imphash_returns_none():
    imphash_by_hash = {"a": "H1", "target": None}
    family_by_hash = {"a": "AgentTesla"}
    assert predict_family_by_imphash("target", None, imphash_by_hash, family_by_hash) is None


def test_predict_family_by_imphash_ignores_unknown_neighbor_labels():
    imphash_by_hash = {"a": "H1", "target": "H1"}
    family_by_hash = {"a": "unknown"}
    assert predict_family_by_imphash("target", "H1", imphash_by_hash, family_by_hash) is None


def test_predict_family_by_imphash_tie_broken_alphabetically():
    imphash_by_hash = {"a": "H1", "b": "H1", "target": "H1"}
    family_by_hash = {"a": "RedLineStealer", "b": "AgentTesla"}
    # one vote each -- deterministic tie-break, alphabetical
    assert predict_family_by_imphash("target", "H1", imphash_by_hash, family_by_hash) == "AgentTesla"


# ---------- combining signals ----------

def test_attribute_family_prefers_capa_malware_family_hit():
    result = attribute_family("target", capa_family_hits=["plugx"], imphash="H1",
                              imphash_by_hash={"target": "H1"}, family_by_hash={})
    assert result == FamilyAttribution(sha256="target", predicted_family="plugx",
                                       method="capa_malware_family")


def test_attribute_family_falls_back_to_imphash_cluster():
    result = attribute_family("target", capa_family_hits=None, imphash="H1",
                              imphash_by_hash={"a": "H1", "target": "H1"},
                              family_by_hash={"a": "AgentTesla"})
    assert result.predicted_family == "AgentTesla"
    assert result.method == "imphash_cluster"


def test_attribute_family_returns_unknown_when_no_signal():
    result = attribute_family("target", capa_family_hits=None, imphash=None,
                              imphash_by_hash={}, family_by_hash={})
    assert result.predicted_family == "unknown"
    assert result.method == "none"


def test_attribute_family_multiple_capa_hits_deterministic():
    result = attribute_family("target", capa_family_hits=["plugx", "donut-loader"],
                              imphash=None, imphash_by_hash={}, family_by_hash={})
    assert result.predicted_family == "donut-loader"  # alphabetically first, deterministic


# ---------- ground truth loading ----------

def test_load_family_ground_truth(tmp_path):
    csv_path = tmp_path / "gt.csv"
    csv_path.write_text("hash,family,signature,tags,query_status\n"
                        "aaa,AgentTesla,AgentTesla,AgentTesla|exe,ok\n"
                        "bbb,unknown,,,\n")
    gt = load_family_ground_truth(str(csv_path))
    assert gt == {"aaa": "AgentTesla", "bbb": "unknown"}


# ---------- macro-F1 ----------

def test_compute_macro_f1_perfect_predictions():
    predictions = {"a": "AgentTesla", "b": "AgentTesla", "c": "RedLineStealer"}
    ground_truth = {"a": "AgentTesla", "b": "AgentTesla", "c": "RedLineStealer"}
    report = compute_macro_f1(predictions, ground_truth)
    assert report.macro_f1 == 1.0
    assert sorted(report.classes) == ["AgentTesla", "RedLineStealer"]


def test_compute_macro_f1_excludes_unknown_ground_truth_from_scoring():
    """A sample whose real family MalwareBazaar itself couldn't determine
    has no true label to score against -- excluding it is honest; silently
    treating 'unknown' as a real class would let the heuristic farm easy
    points by also guessing 'unknown'."""
    predictions = {"a": "AgentTesla", "b": "unknown"}
    ground_truth = {"a": "AgentTesla", "b": "unknown"}
    report = compute_macro_f1(predictions, ground_truth)
    assert report.macro_f1 == 1.0
    assert report.classes == ["AgentTesla"]
    assert report.excluded_unknown_ground_truth == 1


def test_compute_macro_f1_wrong_prediction_is_fn_not_new_class():
    predictions = {"a": "unknown", "b": "RedLineStealer"}
    ground_truth = {"a": "AgentTesla", "b": "RedLineStealer"}
    report = compute_macro_f1(predictions, ground_truth)
    assert report.per_class["AgentTesla"].f1 == 0.0
    assert report.per_class["RedLineStealer"].f1 == 1.0
    assert report.macro_f1 == 0.5


def test_compute_macro_f1_false_positive_hurts_precision():
    predictions = {"a": "AgentTesla", "b": "AgentTesla"}
    ground_truth = {"a": "AgentTesla", "b": "RedLineStealer"}
    report = compute_macro_f1(predictions, ground_truth)
    assert round(report.per_class["AgentTesla"].precision, 4) == 0.5
    assert report.per_class["AgentTesla"].recall == 1.0


def test_compute_macro_f1_no_scored_samples_returns_none():
    report = compute_macro_f1({}, {})
    assert report.macro_f1 is None
    assert report.classes == []


def test_compute_macro_f1_missing_prediction_counts_against_recall():
    """A hash with real ground truth but no prediction at all (e.g. the
    pipeline errored on it) must not be silently dropped -- it should be
    tracked and still counts as a miss for its true class."""
    predictions = {"a": "AgentTesla"}
    ground_truth = {"a": "AgentTesla", "b": "AgentTesla"}
    report = compute_macro_f1(predictions, ground_truth)
    assert report.unscored_missing_predictions == 1
    assert report.per_class["AgentTesla"].recall == 0.5


# ---------- leave-one-out orchestration ----------

def test_predict_all_leave_one_out_excludes_targets_own_label():
    imphash_by_hash = {"a": "H1", "b": "H1"}
    ground_truth = {"a": "AgentTesla", "b": "AgentTesla"}
    predictions = predict_all_leave_one_out(imphash_by_hash, ground_truth)
    # 'a' predicts from 'b's label (and vice versa) -- correct since they share an imphash
    assert predictions["a"].predicted_family == "AgentTesla"
    assert predictions["b"].predicted_family == "AgentTesla"


def test_predict_all_leave_one_out_prefers_capa_hits_when_supplied():
    imphash_by_hash = {"a": "H1"}
    ground_truth = {"a": "AgentTesla"}
    capa_hits = {"a": ["plugx"]}
    predictions = predict_all_leave_one_out(imphash_by_hash, ground_truth, capa_hits)
    assert predictions["a"].predicted_family == "plugx"
    assert predictions["a"].method == "capa_malware_family"


# ---------- end-to-end orchestration against a fake filesystem ----------

def test_run_family_attribution_end_to_end_with_fake_imphash(tmp_path):
    mal_dir = tmp_path / "malicious"
    mal_dir.mkdir()
    for h in ["aaa", "bbb", "ccc"]:
        (mal_dir / f"{h}.bin").write_bytes(b"x")
    gt_csv = tmp_path / "gt.csv"
    gt_csv.write_text(
        "hash,family,signature,tags,query_status\n"
        "aaa,AgentTesla,AgentTesla,AgentTesla,ok\n"
        "bbb,AgentTesla,AgentTesla,AgentTesla,ok\n"
        "ccc,RedLineStealer,RedLineStealer,RedLineStealer,ok\n")
    fake_imphashes = {"aaa": "H1", "bbb": "H1", "ccc": "H2"}

    def fake_imphash_fn(path):
        return fake_imphashes[Path(path).stem]

    report = run_family_attribution(str(mal_dir), str(gt_csv), imphash_fn=fake_imphash_fn)
    # aaa <-> bbb share H1 and both AgentTesla -> both correctly predicted
    # ccc is alone on H2 -> no neighbor -> predicted unknown -> miss
    assert report.scored_samples == 3
    assert report.predictions["aaa"].predicted_family == "AgentTesla"
    assert report.predictions["ccc"].predicted_family == "unknown"
    assert report.macro_f1 is not None
