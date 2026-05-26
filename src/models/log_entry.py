"""
LogEntry dataclass, LogBatch, and Severity enum.

Core data structures for representing parsed log entries throughout
the analysis pipeline.
"""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional


class Severity(Enum):
    """Log severity levels with numeric ordering."""

    DEBUG = "debug"
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"

    @property
    def numeric_value(self) -> int:
        """Get numeric value for severity comparison."""
        values = {
            "debug": 0,
            "info": 1,
            "warning": 2,
            "error": 3,
            "critical": 4,
        }
        return values.get(self.value, 0)

    @classmethod
    def from_string(cls, level: str) -> "Severity":
        """Parse a severity level from string, case-insensitive."""
        level_map = {
            "debug": cls.DEBUG,
            "trace": cls.DEBUG,
            "info": cls.INFO,
            "information": cls.INFO,
            "notice": cls.INFO,
            "warn": cls.WARNING,
            "warning": cls.WARNING,
            "error": cls.ERROR,
            "err": cls.ERROR,
            "critical": cls.CRITICAL,
            "crit": cls.CRITICAL,
            "fatal": cls.CRITICAL,
            "emergency": cls.CRITICAL,
            "emerg": cls.CRITICAL,
            "alert": cls.CRITICAL,
        }
        return level_map.get(level.lower().strip(), cls.INFO)

    def __lt__(self, other: "Severity") -> bool:
        if not isinstance(other, Severity):
            return NotImplemented
        return self.numeric_value < other.numeric_value

    def __le__(self, other: "Severity") -> bool:
        if not isinstance(other, Severity):
            return NotImplemented
        return self.numeric_value <= other.numeric_value

    def __gt__(self, other: "Severity") -> bool:
        if not isinstance(other, Severity):
            return NotImplemented
        return self.numeric_value > other.numeric_value

    def __ge__(self, other: "Severity") -> bool:
        if not isinstance(other, Severity):
            return NotImplemented
        return self.numeric_value >= other.numeric_value


@dataclass
class LogEntry:
    """Represents a single parsed log entry.

    Attributes:
        timestamp: Parsed timestamp of the log entry, if available.
        severity: Severity level of the entry.
        message: The log message content.
        source: Source file or stream identifier.
        line_number: Original line number in the source.
        raw: The original raw log line.
        metadata: Additional structured fields extracted during parsing.
    """

    timestamp: Optional[datetime]
    severity: Severity
    message: str
    source: str
    line_number: int
    raw: str
    metadata: Dict[str, Any] = field(default_factory=dict)

    @property
    def is_error(self) -> bool:
        """Check if this entry is an error or critical level."""
        return self.severity in (Severity.ERROR, Severity.CRITICAL)

    @property
    def is_warning(self) -> bool:
        """Check if this entry is a warning level."""
        return self.severity == Severity.WARNING

    @property
    def has_timestamp(self) -> bool:
        """Check if this entry has a parsed timestamp."""
        return self.timestamp is not None

    def to_dict(self) -> Dict[str, Any]:
        """Serialize the log entry to a dictionary."""
        return {
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "severity": self.severity.value,
            "message": self.message,
            "source": self.source,
            "line_number": self.line_number,
            "metadata": self.metadata,
        }

    def matches_severity(self, min_severity: Severity) -> bool:
        """Check if this entry meets or exceeds a minimum severity."""
        return self.severity.numeric_value >= min_severity.numeric_value

    def __repr__(self) -> str:
        ts_str = self.timestamp.strftime("%H:%M:%S") if self.timestamp else "??:??:??"
        return (
            f"<LogEntry [{self.severity.value.upper()}] "
            f"{ts_str} {self.message[:50]}>"
        )


@dataclass
class LogBatch:
    """A batch of log entries from a single source.

    Attributes:
        entries: List of parsed log entries.
        source: Source identifier (file path, stream name, etc.).
        total_lines: Total number of raw lines in the source.
        parsed_lines: Number of lines successfully parsed.
    """

    entries: List[LogEntry]
    source: str
    total_lines: int
    parsed_lines: int

    @property
    def parse_rate(self) -> float:
        """Calculate the percentage of lines successfully parsed."""
        if self.total_lines == 0:
            return 0.0
        return (self.parsed_lines / self.total_lines) * 100

    @property
    def error_count(self) -> int:
        """Count entries with error or critical severity."""
        return sum(1 for e in self.entries if e.is_error)

    @property
    def warning_count(self) -> int:
        """Count entries with warning severity."""
        return sum(1 for e in self.entries if e.is_warning)

    def filter_by_severity(self, min_severity: Severity) -> List[LogEntry]:
        """Filter entries by minimum severity level."""
        return [e for e in self.entries if e.matches_severity(min_severity)]

    def filter_by_source(self, source: str) -> List[LogEntry]:
        """Filter entries by source identifier."""
        return [e for e in self.entries if e.source == source]

    def get_time_range(self) -> Optional[Dict[str, datetime]]:
        """Get the time range of entries in this batch."""
        timestamped = [e for e in self.entries if e.has_timestamp]
        if not timestamped:
            return None
        timestamps = [e.timestamp for e in timestamped]
        return {
            "start": min(timestamps),  # type: ignore
            "end": max(timestamps),  # type: ignore
        }

    def to_dict(self) -> Dict[str, Any]:
        """Serialize the batch to a dictionary."""
        return {
            "source": self.source,
            "total_lines": self.total_lines,
            "parsed_lines": self.parsed_lines,
            "parse_rate": round(self.parse_rate, 2),
            "error_count": self.error_count,
            "warning_count": self.warning_count,
            "entry_count": len(self.entries),
        }
