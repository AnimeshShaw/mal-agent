"""Bounded LLM adjudication research layer.

Analysis runs once per sample and is frozen into an *evidence bundle*
(bundle.py). Every experimental arm -- EMBER alone, the deterministic
gate, CGEF, an LLM judge on everything, an LLM judge only on routed hard
cases -- is computed offline from the same bundles, so arms differ only in
their decision rule, never in what evidence was collected.
"""
