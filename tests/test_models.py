"""Tests for data models: LogEntry, LogBatch, AnalysisState, Severity."""

import pytest
from datetime import datetime, timedelta

from src.models.log_entry import LogEntry, LogBatch, Severity
from src.models.analysis_state import AnalysisState


class TestSeverity:
    """Tests for the Severity enum."""

    def test_from_string_standard_levels(self):
        assert Severity.from_string("debug") == Severity.DEBUG
        assert Severity.from_string("info") == Severity.INFO
        assert Severity.from_string("warning") == Severity.WARNING
        assert Severity.from_string("error") == Severity.ERROR
        assert Severity.from_string("critical") == Severity.CRITICAL

    def test_from_string_case_insensitive(self):
        assert Severity.from_string("ERROR") == Severity.ERROR
        assert Severity.from_string("Warning") == Severity.WARNING
        assert Severity.from_string("INFO") == Severity.INFO

    def test_from_string_aliases(self):
        assert Severity.from_string("warn") == Severity.WARNING
        assert Severity.from_string("err") == Severity.ERROR
        assert Severity.from_string("crit") == Severity.CRITICAL
        assert Severity.from_string("fatal") == Severity.CRITICAL
        assert Severity.from_string("trace") == Severity.DEBUG
        assert Severity.from_string("notice") == Severity.INFO

    def test_from_string_unknown_defaults_to_info(self):
        assert Severity.from_string("unknown") == Severity.INFO
        assert Severity.from_string("") == Severity.INFO

    def test_numeric_value_ordering(self):
        assert Severity.DEBUG.numeric_value < Severity.INFO.numeric_value
        assert Severity.INFO.numeric_value < Severity.WARNING.numeric_value
        assert Severity.WARNING.numeric_value < Severity.ERROR.numeric_value
        assert Severity.ERROR.numeric_value < Severity.CRITICAL.numeric_value

    def test_comparison_operators(self):
        assert Severity.DEBUG < Severity.INFO
        assert Severity.ERROR > Severity.WARNING
        assert Severity.INFO <= Severity.INFO
        assert Severity.CRITICAL >= Severity.ERROR


class TestLogEntry:
    """Tests for the LogEntry dataclass."""

    def test_create_log_entry(self, sample_timestamp):
        entry = LogEntry(
            timestamp=sample_timestamp,
            severity=Severity.ERROR,
            message="Test error",
            source="test.log",
            line_number=1,
            raw="raw line",
        )
        assert entry.message == "Test error"
        assert entry.severity == Severity.ERROR
        assert entry.line_number == 1

    def test_is_error_property(self, sample_timestamp):
        error_entry = LogEntry(
            timestamp=sample_timestamp, severity=Severity.ERROR,
            message="err", source="t", line_number=1, raw="r",
        )
        critical_entry = LogEntry(
            timestamp=sample_timestamp, severity=Severity.CRITICAL,
            message="crit", source="t", line_number=2, raw="r",
        )
        info_entry = LogEntry(
            timestamp=sample_timestamp, severity=Severity.INFO,
            message="info", source="t", line_number=3, raw="r",
        )
        assert error_entry.is_error is True
        assert critical_entry.is_error is True
        assert info_entry.is_error is False

    def test_is_warning_property(self, sample_timestamp):
        warn_entry = LogEntry(
            timestamp=sample_timestamp, severity=Severity.WARNING,
            message="warn", source="t", line_number=1, raw="r",
        )
        assert warn_entry.is_warning is True

    def test_has_timestamp(self):
        with_ts = LogEntry(
            timestamp=datetime.now(), severity=Severity.INFO,
            message="m", source="s", line_number=1, raw="r",
        )
        without_ts = LogEntry(
            timestamp=None, severity=Severity.INFO,
            message="m", source="s", line_number=1, raw="r",
        )
        assert with_ts.has_timestamp is True
        assert without_ts.has_timestamp is False

    def test_to_dict(self, sample_timestamp):
        entry = LogEntry(
            timestamp=sample_timestamp, severity=Severity.WARNING,
            message="test msg", source="src.log", line_number=5, raw="raw",
            metadata={"key": "val"},
        )
        d = entry.to_dict()
        assert d["severity"] == "warning"
        assert d["message"] == "test msg"
        assert d["line_number"] == 5
        assert d["metadata"] == {"key": "val"}
        assert "timestamp" in d

    def test_matches_severity(self, sample_timestamp):
        entry = LogEntry(
            timestamp=sample_timestamp, severity=Severity.ERROR,
            message="e", source="s", line_number=1, raw="r",
        )
        assert entry.matches_severity(Severity.WARNING) is True
        assert entry.matches_severity(Severity.ERROR) is True
        assert entry.matches_severity(Severity.CRITICAL) is False


class TestLogBatch:
    """Tests for the LogBatch dataclass."""

    def test_parse_rate(self, sample_log_batch):
        assert sample_log_batch.parse_rate == 80.0

    def test_parse_rate_zero_lines(self):
        batch = LogBatch(entries=[], source="x", total_lines=0, parsed_lines=0)
        assert batch.parse_rate == 0.0

    def test_error_count(self, sample_log_batch):
        # sample has 2 ERROR + 1 CRITICAL = 3
        assert sample_log_batch.error_count == 3

    def test_warning_count(self, sample_log_batch):
        # sample has 2 WARNING entries
        assert sample_log_batch.warning_count == 2

    def test_filter_by_severity(self, sample_log_batch):
        errors = sample_log_batch.filter_by_severity(Severity.ERROR)
        assert all(e.severity.numeric_value >= Severity.ERROR.numeric_value for e in errors)

    def test_get_time_range(self, sample_log_batch):
        time_range = sample_log_batch.get_time_range()
        assert time_range is not None
        assert "start" in time_range
        assert "end" in time_range
        assert time_range["start"] <= time_range["end"]

    def test_to_dict(self, sample_log_batch):
        d = sample_log_batch.to_dict()
        assert d["source"] == "/var/log/app.log"
        assert d["total_lines"] == 10
        assert "parse_rate" in d


class TestAnalysisState:
    """Tests for the AnalysisState dataclass."""

    def test_mark_started(self, sample_state):
        sample_state.mark_started()
        assert sample_state.started_at is not None
        assert sample_state.is_complete is False

    def test_mark_completed(self, sample_state):
        sample_state.mark_started()
        sample_state.mark_completed()
        assert sample_state.is_complete is True
        assert sample_state.completed_at is not None

    def test_duration_seconds(self, sample_state):
        sample_state.started_at = datetime(2026, 1, 1, 0, 0, 0)
        sample_state.completed_at = datetime(2026, 1, 1, 0, 0, 5)
        assert sample_state.duration_seconds == 5.0

    def test_add_error(self, sample_state):
        sample_state.add_error("test_agent", "something broke", {"detail": "x"})
        assert len(sample_state.errors) == 1
        assert sample_state.errors[0]["agent"] == "test_agent"
        assert sample_state.has_errors is True

    def test_has_entries(self, sample_state, empty_state):
        assert sample_state.has_entries is True
        assert empty_state.has_entries is False

    def test_entry_count(self, sample_state):
        assert sample_state.entry_count == 8

    def test_reset(self, sample_state):
        sample_state.mark_started()
        sample_state.reset()
        assert sample_state.log_entries == []
        assert sample_state.is_complete is False
        assert sample_state.started_at is None

    def test_get_summary(self, sample_state):
        summary = sample_state.get_summary()
        assert "total_entries" in summary
        assert "is_complete" in summary
        assert summary["total_entries"] == 8

    def test_merge_raw_lines(self, sample_state):
        sample_state.merge_raw_lines(["line1", "line2"], source="new_source")
        assert "line1" in sample_state.raw_lines
        assert sample_state.source_file == "new_source"
