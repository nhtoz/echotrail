"""flightrec — flight recorder & forensics for AI agents (MVP)."""

from .recorder import Recorder, Session
from .store import TraceStore, VerificationResult
from .scan import scan_text, scan_payload, risk_score

__version__ = "0.8.0"
__all__ = ["Recorder", "Session", "TraceStore", "VerificationResult", "scan_text", "scan_payload", "risk_score"]
