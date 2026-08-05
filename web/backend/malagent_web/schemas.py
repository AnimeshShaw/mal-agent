"""Pydantic response models for the web UI's API. Deliberately thin --
malagent.contracts.Verdict already has its own schema; these just shape
the run-registry's own status envelope, not sample-analysis data."""
from __future__ import annotations
from typing import Optional
from pydantic import BaseModel


class AnalysisCreated(BaseModel):
    run_id: str
    status: str


class AnalysisStatus(BaseModel):
    run_id: str
    status: str
    error: Optional[str] = None
    verdict: Optional[dict] = None
