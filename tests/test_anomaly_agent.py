"""Tests for AnomalyAgent."""

import pytest
from datetime import datetime, timedelta

from src.agents.anomaly_agent import AnomalyAgent
from src.models.analysis_state import AnalysisState
from src.models.log_entry import LogEntry, Severity


@pytest.fixture
def agent():
    return AnomalyAgent(config={"z_score_threshold": 2.0, "min_samples": 5})


@pytest.fixture
def state_with_entries():
    """State with timestamped entries including a spike."""
    entries = []
    base_time = datetime(2026, 5, 22, 8, 0, 0)

    # Normal rate: 1 entry per minute for 20 minutes
    for i in range(20):
        entries.append(LogEntry(
            timestamp=base_time + timedelta(minutes=i),
            severity=Severity.INFO,
            message=f"Normal log entry {i}",
            source="test.log",
            line_number=i + 1,
            raw=f"2026-05-22 08:{i:02d}:00 INFO Normal log entry {i}",
        ))

    # Spike: 15 entries in 1 minute
    spike_time = base_time + timedelta(minutes=20)
    for i in range(15):
        entries.append(LogEntry(
            timestamp=spike_time + timedelta(seconds=i * 4),
            severity=Severity.ERROR,
            message=f"Error spike entry {i}",
            source="test.log",
            line_number=21 + i,
            raw=f"2026-05-22 08:20:{i*4:02d} ERROR Error spike entry {i}",
        ))

    state = AnalysisState()
    state.log_entries = entries
    state.total_entries = len(entries)
    return state


@pytest.fixture
def empty_state():
    state = AnalysisState()
    state.log_entries = []
    state.total_entries = 0
    return state


class TestAnomalyAgent:
    """Test anomaly detection."""

    @pytest.mark.asyncio
    async def test_agent_name(self, agent):
        assert agent.name == "anomaly"

    @pytest.mark.asyncio
    async def test_empty_entries(self, agent, empty_state):
        result = await agent.analyze(empty_state)
        assert isinstance(result, dict)

    @pytest.mark.asyncio
    async def test_analyze_with_entries(self, agent, state_with_entries):
        result = await agent.analyze(state_with_entries)
        assert isinstance(result, dict)

    @pytest.mark.asyncio
    async def test_returns_dict_keys(self, agent, state_with_entries):
        result = await agent.analyze(state_with_entries)
        # Should have some standard keys
        assert any(k in result for k in ["anomalies", "findings", "total_anomalies"])

    @pytest.mark.asyncio
    async def test_few_entries_no_crash(self, agent):
        """Agent should handle fewer entries than min_samples gracefully."""
        state = AnalysisState()
        state.log_entries = [
            LogEntry(
                timestamp=datetime(2026, 5, 22, 8, 0, i),
                severity=Severity.INFO,
                message=f"Entry {i}",
                source="test.log",
                line_number=i,
                raw=f"line {i}",
            )
            for i in range(3)
        ]
        state.total_entries = 3
        result = await agent.analyze(state)
        assert isinstance(result, dict)

    @pytest.mark.asyncio
    async def test_no_timestamp_entries(self, agent):
        """Agent should handle entries without timestamps."""
        state = AnalysisState()
        state.log_entries = [
            LogEntry(
                timestamp=None,
                severity=Severity.ERROR,
                message=f"No timestamp {i}",
                source="test.log",
                line_number=i,
                raw=f"ERROR No timestamp {i}",
            )
            for i in range(10)
        ]
        state.total_entries = 10
        result = await agent.analyze(state)
        assert isinstance(result, dict)
