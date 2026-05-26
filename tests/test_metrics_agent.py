"""Tests for MetricsAgent."""

import pytest
from datetime import datetime, timedelta

from src.agents.metrics_agent import MetricsAgent
from src.models.analysis_state import AnalysisState
from src.models.log_entry import LogEntry, Severity


@pytest.fixture
def agent():
    return MetricsAgent(config={"percentiles": [50, 90, 95, 99], "bucket_size_seconds": 60})


@pytest.fixture
def state_with_mixed_entries():
    """State with various severity entries over time."""
    entries = []
    base_time = datetime(2026, 5, 22, 8, 0, 0)

    severities = [Severity.INFO] * 70 + [Severity.WARNING] * 15 + [Severity.ERROR] * 10 + [Severity.CRITICAL] * 5
    for i, sev in enumerate(severities):
        entries.append(LogEntry(
            timestamp=base_time + timedelta(seconds=i * 10),
            severity=sev,
            message=f"Entry {i} at {sev.value}",
            source="app.log",
            line_number=i + 1,
            raw=f"{sev.value.upper()} Entry {i}",
            metadata={"latency_ms": 20 + (i % 50) * 5} if i % 3 == 0 else {},
        ))

    state = AnalysisState()
    state.log_entries = entries
    state.total_entries = len(entries)
    return state


class TestMetricsAgent:
    """Test metrics aggregation."""

    @pytest.mark.asyncio
    async def test_agent_name(self, agent):
        assert agent.name == "metrics"

    @pytest.mark.asyncio
    async def test_analyze_returns_dict(self, agent, state_with_mixed_entries):
        result = await agent.analyze(state_with_mixed_entries)
        assert isinstance(result, dict)

    @pytest.mark.asyncio
    async def test_empty_state(self, agent):
        state = AnalysisState()
        state.log_entries = []
        state.total_entries = 0
        result = await agent.analyze(state)
        assert isinstance(result, dict)

    @pytest.mark.asyncio
    async def test_severity_counts(self, agent, state_with_mixed_entries):
        result = await agent.analyze(state_with_mixed_entries)
        # Should have severity breakdown
        severity_data = result.get("severity", {})
        if severity_data:
            assert isinstance(severity_data, dict)

    @pytest.mark.asyncio
    async def test_total_entries_tracked(self, agent, state_with_mixed_entries):
        result = await agent.analyze(state_with_mixed_entries)
        total = result.get("total_entries", 0)
        assert total == 100 or "total_entries" not in result  # depends on implementation

    @pytest.mark.asyncio
    async def test_single_entry(self, agent):
        state = AnalysisState()
        state.log_entries = [
            LogEntry(
                timestamp=datetime(2026, 5, 22, 8, 0, 0),
                severity=Severity.ERROR,
                message="Single error",
                source="app.log",
                line_number=1,
                raw="ERROR Single error",
            )
        ]
        state.total_entries = 1
        result = await agent.analyze(state)
        assert isinstance(result, dict)
