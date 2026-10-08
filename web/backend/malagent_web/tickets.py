"""Short-lived, single-use, run-scoped tickets for the SSE progress stream.

`EventSource` cannot set a custom header, so it can't carry the real
`X-Mal-Agent-Token` bearer token -- and a long-lived secret in a URL
query string ends up in browser history, proxy access logs, and the
Referer header of anything the page later links to. A client that
already holds the real token exchanges it (via a normal, header-
authenticated POST) for a ticket that is good for one connection to one
run, expires quickly, and is worthless to anyone who later reads it out
of a log."""
from __future__ import annotations
import secrets
import threading
import time
from dataclasses import dataclass

_DEFAULT_TTL_S = 60


@dataclass
class _Ticket:
    run_id: str
    expires_at: float


class TicketStore:
    def __init__(self, ttl_s: float = _DEFAULT_TTL_S):
        self.ttl_s = ttl_s
        self._tickets: dict[str, _Ticket] = {}
        self._lock = threading.Lock()

    def mint(self, run_id: str) -> str:
        ticket = secrets.token_urlsafe(24)
        with self._lock:
            self._gc()
            self._tickets[ticket] = _Ticket(run_id=run_id, expires_at=time.monotonic() + self.ttl_s)
        return ticket

    def redeem(self, ticket: str, run_id: str) -> bool:
        """Single-use: valid only once, only for the run it was minted for."""
        with self._lock:
            t = self._tickets.pop(ticket, None)
        if t is None:
            return False
        return t.run_id == run_id and time.monotonic() < t.expires_at

    def _gc(self) -> None:
        now = time.monotonic()
        expired = [k for k, t in self._tickets.items() if t.expires_at <= now]
        for k in expired:
            del self._tickets[k]
