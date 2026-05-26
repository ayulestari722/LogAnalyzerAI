"""Severity classification and scoring logic."""

from __future__ import annotations

from enum import IntEnum
from typing import Any


class Severity(IntEnum):
    """Log finding severity levels, ordered by importance."""
    CRITICAL = 5
    HIGH = 4
    MEDIUM = 3
    LOW = 2
    INFO = 1

    @classmethod
    def from_string(cls, value: str) -> "Severity":
        """Parse severity from string (case-insensitive)."""
        mapping = {
            "critical": cls.CRITICAL,
            "crit": cls.CRITICAL,
            "fatal": cls.CRITICAL,
            "emergency": cls.CRITICAL,
            "emerg": cls.CRITICAL,
            "high": cls.HIGH,
            "error": cls.HIGH,
            "err": cls.HIGH,
            "medium": cls.MEDIUM,
            "warning": cls.MEDIUM,
            "warn": cls.MEDIUM,
            "low": cls.LOW,
            "notice": cls.LOW,
            "info": cls.INFO,
            "informational": cls.INFO,
            "debug": cls.INFO,
        }
        return mapping.get(value.lower().strip(), cls.INFO)

    @property
    def label(self) -> str:
        """Human-readable label."""
        return self.name.capitalize()

    @property
    def color(self) -> str:
        """ANSI color code for terminal output."""
        colors = {
            self.CRITICAL: "\033[35m",  # magenta
            self.HIGH: "\033[31m",      # red
            self.MEDIUM: "\033[33m",    # yellow
            self.LOW: "\033[36m",       # cyan
            self.INFO: "\033[37m",      # white
        }
        return colors.get(self, "\033[0m")


class SeverityScorer:
    """Calculates weighted severity scores for findings.

    Uses configurable weights per severity level to produce
    a normalized score (0-100) for a collection of findings.
    """

    DEFAULT_WEIGHTS = {
        Severity.CRITICAL: 10,
        Severity.HIGH: 7,
        Severity.MEDIUM: 4,
        Severity.LOW: 2,
        Severity.INFO: 1,
    }

    def __init__(self, weights: dict[Severity, int] | None = None, threshold: float = 50.0):
        self.weights = weights or self.DEFAULT_WEIGHTS
        self.threshold = threshold

    @classmethod
    def from_config(cls, config: dict[str, Any]) -> "SeverityScorer":
        """Create scorer from configuration dictionary."""
        severity_config = config.get("severity", {})
        raw_weights = severity_config.get("weights", {})
        threshold = severity_config.get("score_threshold", 50.0)

        weights = {}
        for name, weight in raw_weights.items():
            sev = Severity.from_string(name)
            weights[sev] = int(weight)

        return cls(weights=weights if weights else None, threshold=threshold)

    def score_findings(self, findings: list[dict[str, Any]]) -> float:
        """Calculate weighted score from a list of findings.

        Each finding should have a 'severity' key (string or Severity enum).

        Returns:
            Normalized score (0-100).
        """
        if not findings:
            return 0.0

        total_weight = 0
        max_possible = len(findings) * self.weights.get(Severity.CRITICAL, 10)

        for finding in findings:
            sev_raw = finding.get("severity", "info")
            if isinstance(sev_raw, Severity):
                severity = sev_raw
            else:
                severity = Severity.from_string(str(sev_raw))
            total_weight += self.weights.get(severity, 1)

        if max_possible == 0:
            return 0.0

        return min(100.0, (total_weight / max_possible) * 100)

    def classify_overall(self, score: float) -> Severity:
        """Classify overall severity based on score."""
        if score >= 80:
            return Severity.CRITICAL
        elif score >= 60:
            return Severity.HIGH
        elif score >= 40:
            return Severity.MEDIUM
        elif score >= 20:
            return Severity.LOW
        else:
            return Severity.INFO

    def exceeds_threshold(self, score: float) -> bool:
        """Check if score exceeds the configured threshold."""
        return score >= self.threshold

    def get_severity_distribution(self, findings: list[dict[str, Any]]) -> dict[str, int]:
        """Count findings by severity level."""
        distribution: dict[str, int] = {s.label: 0 for s in Severity}
        for finding in findings:
            sev_raw = finding.get("severity", "info")
            if isinstance(sev_raw, Severity):
                severity = sev_raw
            else:
                severity = Severity.from_string(str(sev_raw))
            distribution[severity.label] += 1
        return distribution
