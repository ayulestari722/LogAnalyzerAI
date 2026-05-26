"""Shared fixtures for LogAnalyzerAI tests."""

import pytest
from datetime import datetime, timedelta
from typing import List

from src.models.log_entry import LogEntry, LogBatch, Severity
from src.models.analysis_state import AnalysisState


@pytest.fixture
def sample_timestamp():
    """A fixed timestamp for deterministic tests."""
    return datetime(2026, 5, 20, 10, 0, 0)


@pytest.fixture
def sample_log_entries(sample_timestamp) -> List[LogEntry]:
    """A list of sample LogEntry objects covering various severities."""
    base = sample_timestamp
    return [
        LogEntry(
            timestamp=base,
            severity=Severity.INFO,
            message="Application started successfully",
            source="/var/log/app.log",
            line_number=1,
            raw="2026-05-20 10:00:00 INFO Application started successfully",
            metadata={"logger": "main"},
        ),
        LogEntry(
            timestamp=base + timedelta(seconds=10),
            severity=Severity.WARNING,
            message="High memory usage detected: 85%",
            source="/var/log/app.log",
            line_number=2,
            raw="2026-05-20 10:00:10 WARNING High memory usage detected: 85%",
            metadata={"logger": "monitor"},
        ),
        LogEntry(
            timestamp=base + timedelta(seconds=20),
            severity=Severity.ERROR,
            message="Connection refused to database server at 10.0.0.5:5432",
            source="/var/log/app.log",
            line_number=3,
            raw="2026-05-20 10:00:20 ERROR Connection refused to database server at 10.0.0.5:5432",
            metadata={"logger": "db"},
        ),
        LogEntry(
            timestamp=base + timedelta(seconds=30),
            severity=Severity.CRITICAL,
            message="Out of memory: killed process 1234",
            source="/var/log/system.log",
            line_number=4,
            raw="2026-05-20 10:00:30 CRITICAL Out of memory: killed process 1234",
            metadata={"logger": "kernel"},
        ),
        LogEntry(
            timestamp=base + timedelta(seconds=40),
            severity=Severity.DEBUG,
            message="Processing request session_id=abc123def456",
            source="/var/log/app.log",
            line_number=5,
            raw="2026-05-20 10:00:40 DEBUG Processing request session_id=abc123def456",
            metadata={"logger": "handler"},
        ),
        LogEntry(
            timestamp=base + timedelta(seconds=50),
            severity=Severity.ERROR,
            message="Timeout connecting to service at http://api.example.com/v1/users",
            source="/var/log/app.log",
            line_number=6,
            raw="2026-05-20 10:00:50 ERROR Timeout connecting to service",
            metadata={"logger": "http"},
        ),
        LogEntry(
            timestamp=base + timedelta(seconds=60),
            severity=Severity.INFO,
            message="GET /api/health 200 in 12ms",
            source="/var/log/access.log",
            line_number=7,
            raw='192.168.1.1 - - [20/May/2026:10:01:00 +0000] "GET /api/health HTTP/1.1" 200 45',
            metadata={"method": "GET", "path": "/api/health", "status": 200, "request_time": "0.012"},
        ),
        LogEntry(
            timestamp=base + timedelta(seconds=70),
            severity=Severity.WARNING,
            message="POST /api/login 401 in 150ms",
            source="/var/log/access.log",
            line_number=8,
            raw='192.168.1.2 - - [20/May/2026:10:01:10 +0000] "POST /api/login HTTP/1.1" 401 89',
            metadata={"method": "POST", "path": "/api/login", "status": 401, "request_time": "0.150"},
        ),
    ]


@pytest.fixture
def sample_log_batch(sample_log_entries) -> LogBatch:
    """A sample LogBatch."""
    return LogBatch(
        entries=sample_log_entries,
        source="/var/log/app.log",
        total_lines=10,
        parsed_lines=8,
    )


@pytest.fixture
def sample_state(sample_log_entries, sample_log_batch) -> AnalysisState:
    """A sample AnalysisState pre-populated with entries."""
    state = AnalysisState(
        target_path="/var/log",
        files_analyzed=2,
        file_paths=["/var/log/app.log", "/var/log/access.log"],
    )
    state.log_entries = sample_log_entries
    state.log_batch = sample_log_batch
    state.total_entries = len(sample_log_entries)
    return state


@pytest.fixture
def empty_state() -> AnalysisState:
    """An empty AnalysisState with no entries."""
    return AnalysisState(target_path="/tmp/empty")


@pytest.fixture
def sample_config():
    """A sample configuration dictionary."""
    return {
        "orchestrator": {
            "timeout_per_agent": 30.0,
            "max_concurrent_agents": 6,
            "retry_failed_agents": False,
        },
        "agents": {
            "parser": {"enabled": True, "formats": ["json", "syslog", "apache", "nginx"]},
            "anomaly": {"enabled": True, "z_score_threshold": 2.5, "min_samples": 10},
            "pattern": {"enabled": True, "max_patterns": 100, "min_frequency": 3},
            "correlation": {"enabled": True, "time_window_seconds": 60, "min_correlation": 0.7},
            "alert": {"enabled": True, "critical_threshold": 0.9, "high_threshold": 0.7},
            "metrics": {"enabled": True, "percentiles": [50, 90, 95, 99], "bucket_size_seconds": 60},
            "summary": {"enabled": True, "max_findings": 50, "include_recommendations": True},
        },
        "output": {
            "format": "markdown",
            "include_raw_data": False,
            "max_examples_per_finding": 5,
            "sarif_version": "2.1.0",
        },
        "severity": {
            "weights": {"critical": 10, "high": 7, "medium": 4, "low": 2, "info": 1},
            "score_threshold": 50,
        },
        "logging": {
            "level": "INFO",
            "format": "rich",
            "file": None,
        },
    }


@pytest.fixture
def many_error_entries(sample_timestamp) -> List[LogEntry]:
    """Generate many error entries for burst/spike detection tests."""
    base = sample_timestamp
    entries = []
    for i in range(20):
        entries.append(LogEntry(
            timestamp=base + timedelta(seconds=i * 2),
            severity=Severity.ERROR,
            message=f"Error #{i}: Connection timeout to service",
            source="/var/log/app.log",
            line_number=i + 1,
            raw=f"2026-05-20 10:00:{i*2:02d} ERROR Error #{i}: Connection timeout",
            metadata={},
        ))
    return entries


@pytest.fixture
def access_log_entries(sample_timestamp) -> List[LogEntry]:
    """Access log entries with latency metadata."""
    base = sample_timestamp
    entries = []
    paths = ["/api/users", "/api/health", "/api/orders", "/api/login"]
    for i in range(20):
        status = 200 if i % 5 != 0 else 500
        sev = Severity.INFO if status < 400 else Severity.ERROR
        entries.append(LogEntry(
            timestamp=base + timedelta(seconds=i * 5),
            severity=sev,
            message=f"GET {paths[i % 4]} {status}",
            source="/var/log/access.log",
            line_number=i + 1,
            raw=f"request line {i}",
            metadata={
                "method": "GET",
                "path": paths[i % 4],
                "status": status,
                "request_time": str(0.05 + i * 0.01),
                "size": str(1024 + i * 100),
            },
        ))
    return entries
