"""TicketStore: short-lived, single-use, run-scoped SSE tickets."""
from __future__ import annotations
from malagent_web.tickets import TicketStore


def test_mint_then_redeem_succeeds_once():
    store = TicketStore()
    t = store.mint("run-1")
    assert store.redeem(t, "run-1") is True
    assert store.redeem(t, "run-1") is False  # single-use


def test_redeem_rejects_wrong_run_id():
    store = TicketStore()
    t = store.mint("run-1")
    assert store.redeem(t, "run-2") is False


def test_redeem_rejects_unknown_ticket():
    store = TicketStore()
    assert store.redeem("not-a-real-ticket", "run-1") is False


def test_ticket_expires(monkeypatch):
    store = TicketStore(ttl_s=10)
    t = store.mint("run-1")
    import time as time_mod
    now = time_mod.monotonic()
    monkeypatch.setattr(time_mod, "monotonic", lambda: now + 11)
    assert store.redeem(t, "run-1") is False


def test_tickets_are_unguessable():
    store = TicketStore()
    a, b = store.mint("run-1"), store.mint("run-1")
    assert a != b and len(a) >= 24
