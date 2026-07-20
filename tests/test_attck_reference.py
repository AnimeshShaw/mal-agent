"""Sanity checks on the local ATT&CK technique reference table (M4)."""
from __future__ import annotations
from malagent.attck_reference import ATTACK_TECHNIQUES, technique_name


def test_known_technique_resolves():
    assert technique_name("T1055") == "Process Injection"


def test_unknown_technique_returns_none_not_a_guess():
    assert technique_name("T9999") is None


def test_table_covers_a_broad_set_of_techniques():
    # Sanity floor, not an exact count -- the table is sourced from an external
    # CTI dump and may be regenerated with a different (larger) version later.
    assert len(ATTACK_TECHNIQUES) > 500


def test_all_keys_look_like_technique_ids():
    import re
    pattern = re.compile(r"^T\d{4}(\.\d{3})?$")
    assert all(pattern.match(k) for k in ATTACK_TECHNIQUES)
