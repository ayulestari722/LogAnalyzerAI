"""Tests for CorrelationAgent."""

import pytest
from datetime import datetime, timedelta

from src.agents.correlation_agent import CorrelationAgent
from src.models.analysis_state import AnalysisState
from src.models.log_entry import LogEntry, Severity


@pytest.fixture
def agent():
    return CorrelationAgent(config={"time_window_seconds": 60, "min_correlation": 0.5})


@pytest.fixture
def state_with_correlated_events():
    """State with events that should correlate (same timeframe, related messages)."""
    entries = []
    base_time = datetime(2026, 5, 22, 8, 10, 0)

    # Cluster 1: DB failure cascade (within 5 seconds)
    entries.append(LogEntry(timestamp=base_time, severity=Severity.ERROR, message="Database connection timeout", source="app.log", line_number=1, raw="ERROR Database connection timeout", metadata={"component": "db"}))
    entries.append(LogEntry(timestamp=base_time + timedelta(seconds=1), severity=Severity.ERROR, message="Connection pool exhausted", source="app.log", line_number=2, raw="ERROR Connection pool exhausted", metadata={"component": "db"}))
    entries.append(LogEntry(timestamp=base_time + timedelta(seconds=2), severity=Severity.CRITICAL, message="All database connections lost", source="app.log", line_number=3, raw="CRITICAL All database connections lost", metadata={"component": "db"}))
    entries.append(LogEntry(timestamp=base_time + timedelta(seconds=3), severity=Severity.ERROR, message="23 requests failed due to database", source="app.log", line_number=4, raw="ERROR 23 requests failed", metadata={"component": "http"}))

    # Gap: 10 minutes of normal
    for i in range(10):
        entries.append(LogEntry(timestamp=base_time + timedelta(minutes=5+i), severity=Severity.INFO, message=f"Normal operation {i}", source="app.log", line_number=5+i, raw=f"INFO Normal {i}"))

    state = AnalysisState()
    state.log_entries = entries
    state.total_entries = len(entries)
    return state


class TestCorrelationAgent:
    """Test event correlation."""

    @pytest.mark.asyncio
    async def test_agent_name(self, agent):
        assert agent.name == "correlation"

    @pytest.mark.asyncio
    async def test_analyze_returns_dict(self, agent, state_with_correlated_events):
        result = await agent.analyze(state_with_correlated_events)
        assert isinstance(result, dict)

    @pytest.mark.asyncio
    async def test_empty_state(self, agent):
        state = AnalysisState()
        state.log_entries = []
        state.total_entries = 0
        result = await agent.analyze(state)
        assert isinstance(result, dict)

    @pytest.mark.asyncio
    async def test_single_entry(self, agent):
        state = AnalysisState()
        state.log_entries = [
            LogEntry(timestamp=datetime(2026, 5, 22, 8, 0, 0), severity=Severity.ERROR, message="Lone error", source="app.log", line_number=1, raw="ERROR Lone error")
        ]
        state.total_entries = 1
        result = await agent.analyze(state)
        assert isinstance(result, dict)

    @pytest.mark.asyncio
    async def test_result_keys(self, agent, state_with_correlated_events):
        result = await agent.analyze(state_with_correlated_events)
        assert any(k in result for k in ["correlation_groups", "findings", "temporal_clusters", "causal_chains"])

    @pytest.mark.asyncio
    async def test_no_timestamp_entries(self, agent):
        state = AnalysisState()
        state.log_entries = [
            LogEntry(timestamp=None, severity=Severity.ERROR, message=f"No ts {i}", source="app.log", line_number=i, raw=f"ERROR No ts {i}")
            for i in range(5)
        ]
        state.total_entries = 5
        result = await agent.analyze(state)
        assert isinstance(result, dict)
