"""Shared contracts for forensic analysis modules.

Each module is independent, takes a verified working copy path, and returns an
`AnalysisResult` containing:
  - `summary`    : structured dictionary describing the artifact
  - `findings`   : list of finding dicts (may carry `is_hypothesis`)
  - `events`     : normalized timeline events (UTC datetimes)
  - `errors`     : non-fatal processing notes

Modules MUST NOT mutate the input. They read from the working copy only.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any


@dataclass
class AnalysisResult:
    module: str
    summary: dict[str, Any] = field(default_factory=dict)
    findings: list[dict[str, Any]] = field(default_factory=list)
    events: list[dict[str, Any]] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    def add_event(self, event_time_utc: datetime, source_module: str, description: str,
                  category: str | None = None, properties: dict | None = None,
                  confidence: float = 0.8) -> None:
        if event_time_utc.tzinfo is None:
            event_time_utc = event_time_utc.replace(tzinfo=timezone.utc)
        self.events.append({
            "event_time_utc": event_time_utc,
            "source_module": source_module,
            "description": description,
            "category": category,
            "properties": properties or {},
            "confidence": confidence,
        })

    def add_finding(self, title: str, description: str = "", severity: str = "info",
                    is_hypothesis: bool = False, confidence: float = 0.0,
                    properties: dict | None = None) -> None:
        self.findings.append({
            "title": title,
            "description": description,
            "severity": severity,
            "is_hypothesis": is_hypothesis,
            "confidence": confidence,
            "properties": properties or {},
        })


class ForensicsModule(ABC):
    """Base class for all independent analysis modules."""

    name: str = "base"
    display_name: str = "Base"
    description: str = ""
    supported_types: list[str] = []

    @abstractmethod
    def analyze(self, working_copy_path: str, context: dict[str, Any] | None = None) -> AnalysisResult:
        raise NotImplementedError

    # Compatibility with per-module implementations that expose `run`.
    def run(self, working_copy_path: str, context: dict[str, Any] | None = None) -> AnalysisResult:
        return self.analyze(working_copy_path, context)