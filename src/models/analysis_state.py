"""
AnalysisState — Tracks pipeline progress and agent results.

Central state object passed through the analysis pipeline, accumulating
results from each agent and tracking overall progress.
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional

from src.models.log_entry import LogEntry, LogBatch


@dataclass
class AnalysisState:
    """Shared state object for the analysis pipeline.

    Passed to each agent during execution. Agents read from and write to
    this state to share data and results.

    Attributes:
        raw_lines: Original raw log lines before parsing.
        log_entries: Parsed log entries (populated by ParserAgent).
        log_batch: Batch metadata (populated by ParserAgent).
        agent_results: Results from each agent, keyed by agent name.
        source_file: Path or identifier of the source being analyzed.
        config: Pipeline configuration dictionary.
        is_complete: Whether the pipeline has finished.
        started_at: Timestamp when analysis started.
        completed_at: Timestamp when analysis completed.
        errors: List of errors encountered during pipeline execution.
    """

    raw_lines: List[str] = field(default_factory=list)
    log_entries: List[LogEntry] = field(default_factory=list)
    log_batch: Optional[LogBatch] = None
    agent_results: Dict[str, Any] = field(default_factory=dict)
    all_findings: List[Dict[str, Any]] = field(default_factory=list)
    source_file: Optional[str] = None
    target_path: str = ""
    files_analyzed: int = 0
    file_paths: List[str] = field(default_factory=list)
    total_entries: int = 0
    config: Dict[str, Any] = field(default_factory=dict)
    is_complete: bool = False
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    errors: List[Dict[str, Any]] = field(default_factory=list)

    def mark_started(self) -> None:
        """Mark the analysis as started."""
        self.started_at = datetime.now()
        self.is_complete = False

    def mark_completed(self) -> None:
        """Mark the analysis as completed."""
        self.completed_at = datetime.now()
        self.is_complete = True

    def add_error(self, agent_name: str, error: str, details: Optional[Dict[str, Any]] = None) -> None:
        """Record an error that occurred during pipeline execution."""
        self.errors.append({
            "agent": agent_name,
            "error": error,
            "details": details or {},
            "timestamp": datetime.now().isoformat(),
        })

    @property
    def duration_seconds(self) -> Optional[float]:
        """Calculate total analysis duration in seconds."""
        if self.started_at and self.completed_at:
            return (self.completed_at - self.started_at).total_seconds()
        return None

    @property
    def has_entries(self) -> bool:
        """Check if any log entries have been parsed."""
        return len(self.log_entries) > 0

    @property
    def entry_count(self) -> int:
        """Get the number of parsed log entries."""
        return len(self.log_entries)

    @property
    def source_count(self) -> int:
        """Get the number of unique sources."""
        return len(set(e.source for e in self.log_entries))

    @property
    def agents_completed(self) -> List[str]:
        """Get list of agents that have completed."""
        return list(self.agent_results.keys())

    @property
    def has_errors(self) -> bool:
        """Check if any pipeline errors occurred."""
        return len(self.errors) > 0

    def get_agent_result(self, agent_name: str) -> Optional[Dict[str, Any]]:
        """Get results from a specific agent."""
        return self.agent_results.get(agent_name)

    def merge_raw_lines(self, lines: List[str], source: Optional[str] = None) -> None:
        """Add raw lines to the state, optionally updating source."""
        self.raw_lines.extend(lines)
        if source:
            self.source_file = source

    def get_summary(self) -> Dict[str, Any]:
        """Get a summary of the current state."""
        return {
            "total_raw_lines": len(self.raw_lines),
            "total_entries": self.entry_count,
            "source_count": self.source_count,
            "agents_completed": self.agents_completed,
            "is_complete": self.is_complete,
            "has_errors": self.has_errors,
            "error_count": len(self.errors),
            "duration_seconds": self.duration_seconds,
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
        }

    def reset(self) -> None:
        """Reset the state for a new analysis run."""
        self.raw_lines = []
        self.log_entries = []
        self.log_batch = None
        self.agent_results = {}
        self.is_complete = False
        self.started_at = None
        self.completed_at = None
        self.errors = []

    def to_dict(self) -> Dict[str, Any]:
        """Serialize the full state to a dictionary."""
        return {
            "summary": self.get_summary(),
            "agent_results": self.agent_results,
            "errors": self.errors,
            "source_file": self.source_file,
        }
