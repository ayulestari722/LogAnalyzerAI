"""Tests for AlertAgent."""

import pytest
from datetime import datetime

from src.agents.alert_agent import AlertAgent
from src.models.analysis_state import AnalysisState
from src.models.log_entry import LogEntry, Severity


@pytest.fixture
def agent():
    return AlertAgent(config={
        "critical_threshold": 0.9,
        "high_threshold": 0.7,
        "medium_threshold": 0.4,
    })


@pytest.fixture
def state_with_errors():
    """State with mix of severities."""
    entries = []
    base_time = datetime(2026, 5, 22, 8, 0, 0)

    # 50 INFO entries
    for i in range(50):
        entries.append(LogEntry(
            timestamp=base_time,
            severity=Severity.INFO,
            message=f"Info message {i}",
            source="app.log",
            line_number=i + 1,
            raw=f"INFO Info message {i}",
        ))

    # 10 ERROR entries
    for i in range(10):
        entries.append(LogEntry(
            timestamp=base_time,
            severity=Severity.ERROR,
            message=f"Error message {i}",
            source="app.log",
            line_number=51 + i,
            raw=f"ERROR Error message {i}",
        ))

    # 3 CRITICAL entries
    for i in range(3):
        entries.append(LogEntry(
            timestamp=base_time,
            severity=Severity.CRITICAL,
            message=f"Critical failure {i}",
            source="app.log",
            line_number=61 + i,
            raw=f"CRITICAL Critical failure {i}",
        ))

    state = AnalysisState()
    state.log_entries = entries
    state.total_entries = len(entries)
    return state


class TestAlertAgent:
    """Test alert generation."""

    @pytest.mark.asyncio
    async def test_agent_name(self, agent):
        assert agent.name == "alert"

    @pytest.mark.asyncio
    async def test_analyze_returns_dict(self, agent, state_with_errors):
        result = await agent.analyze(state_with_errors)
        assert isinstance(result, dict)

    @pytest.mark.asyncio
    async def test_empty_state(self, agent):
        state = AnalysisState()
        state.log_entries = []
        state.total_entries = 0
        result = await agent.analyze(state)
        assert isinstance(result, dict)

    @pytest.mark.asyncio
    async def test_all_info_no_alerts(self, agent):
        state = AnalysisState()
        state.log_entries = [
            LogEntry(
                timestamp=datetime(2026, 5, 22, 8, 0, 0),
                severity=Severity.INFO,
                message=f"All good {i}",
                source="app.log",
                line_number=i,
                raw=f"INFO All good {i}",
            )
            for i in range(20)
        ]
        state.total_entries = 20
        result = await agent.analyze(state)
        alerts = result.get("alerts", [])
        # With only INFO entries, should have no critical/high alerts
        critical_alerts = [a for a in alerts if isinstance(a, dict) and a.get("severity") in ("critical", "high")]
        assert len(critical_alerts) == 0

    @pytest.mark.asyncio
    async def test_result_has_expected_keys(self, agent, state_with_errors):
        result = await agent.analyze(state_with_errors)
        assert any(k in result for k in ["alerts", "findings", "total_alerts", "rule_evaluations"])
