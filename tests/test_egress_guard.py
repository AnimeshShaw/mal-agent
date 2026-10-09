"""EgressGuard.allowed() had no dedicated test coverage at all before this
file -- only indirectly exercised through ModelRouter/agent tests. Direct
coverage here, plus the new hash_lookup artifact class: a hash isn't raw bytes or pseudocode, but it's still egress
and needs its own explicit opt-in flag, not silent reuse of an existing
one (e.g. allow_pseudocode_egress=True should NOT also silently permit
hash lookups)."""
from __future__ import annotations
from malagent.contracts import EgressPolicy
from malagent.models import EgressGuard


def test_local_always_allowed_regardless_of_policy():
    guard = EgressGuard(EgressPolicy(allow_cloud=False))
    ok, _ = guard.allowed("local", "raw_bytes")
    assert ok is True


def test_cloud_disabled_by_policy_blocks_everything():
    guard = EgressGuard(EgressPolicy(allow_cloud=False))
    ok, reason = guard.allowed("cloud", "derived")
    assert ok is False
    assert "disabled" in reason.lower()


def test_raw_bytes_blocked_by_default():
    guard = EgressGuard(EgressPolicy(allow_cloud=True))
    ok, _ = guard.allowed("cloud", "raw_bytes")
    assert ok is False


def test_raw_bytes_allowed_when_explicitly_opted_in():
    guard = EgressGuard(EgressPolicy(allow_cloud=True, allow_raw_bytes_egress=True))
    ok, _ = guard.allowed("cloud", "raw_bytes")
    assert ok is True


def test_pseudocode_blocked_by_default():
    guard = EgressGuard(EgressPolicy(allow_cloud=True))
    ok, _ = guard.allowed("cloud", "pseudocode")
    assert ok is False


def test_pseudocode_allowed_when_explicitly_opted_in():
    guard = EgressGuard(EgressPolicy(allow_cloud=True, allow_pseudocode_egress=True))
    ok, _ = guard.allowed("cloud", "pseudocode")
    assert ok is True


def test_derived_permitted_by_default_when_cloud_allowed():
    guard = EgressGuard(EgressPolicy(allow_cloud=True))
    ok, _ = guard.allowed("cloud", "derived")
    assert ok is True


def test_hash_lookup_blocked_by_default():
    """A hash isn't raw bytes or pseudocode, but it's still egress --
    needs its own explicit opt-in, not silent reuse of an existing flag."""
    guard = EgressGuard(EgressPolicy(allow_cloud=True))
    ok, reason = guard.allowed("cloud", "hash_lookup")
    assert ok is False
    assert "hash" in reason.lower()


def test_hash_lookup_allowed_when_explicitly_opted_in():
    guard = EgressGuard(EgressPolicy(allow_cloud=True, allow_hash_lookup=True))
    ok, _ = guard.allowed("cloud", "hash_lookup")
    assert ok is True


def test_pseudocode_opt_in_does_not_silently_permit_hash_lookup():
    """Each artifact class needs its own explicit flag -- opting into
    pseudocode egress (e.g. for Ghidra decompile summaries) must not
    accidentally also permit hash lookups, a completely different kind
    of egress with a different risk profile."""
    guard = EgressGuard(EgressPolicy(allow_cloud=True, allow_pseudocode_egress=True))
    ok, _ = guard.allowed("cloud", "hash_lookup")
    assert ok is False


def test_hash_lookup_still_blocked_when_cloud_disabled():
    guard = EgressGuard(EgressPolicy(allow_cloud=False, allow_hash_lookup=True))
    ok, _ = guard.allowed("cloud", "hash_lookup")
    assert ok is False
