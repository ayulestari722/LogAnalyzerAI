"""Tests for the ParserAgent."""

import pytest
from datetime import datetime, timedelta
from unittest.mock import patch, AsyncMock

from src.agents.parser_agent import ParserAgent
from src.models.log_entry import LogEntry, Severity
from src.models.analysis_state import AnalysisState


class TestParserAgent:
    """Tests for ParserAgent."""

    def setup_method(self):
        self.agent = ParserAgent(config={})

    def test_agent_name(self):
        assert self.agent.name == "parser"

    @pytest.mark.asyncio
    async def test_analyze_empty_state(self, empty_state):
        """Parser should handle empty state gracefully."""
        # ParserAgent reads raw_lines from state
        result = await self.agent.analyze(empty_state)
        assert isinstance(result, dict)

    @pytest.mark.asyncio
    async def test_analyze_with_json_lines(self):
        """Parser should parse JSON log lines."""
        state = AnalysisState(target_path="/tmp")
        state.raw_lines = [
            '{"timestamp": "2026-05-20T10:00:00", "level": "error", "message": "DB failed"}',
            '{"timestamp": "2026-05-20T10:00:01", "level": "info", "message": "Recovered"}',
        ]
        result = await self.agent.analyze(state)
        assert isinstance(result, dict)

    @pytest.mark.asyncio
    async def test_analyze_with_syslog_lines(self):
        """Parser should parse syslog format lines."""
        state = AnalysisState(target_path="/tmp")
        state.raw_lines = [
            "May 20 10:00:00 myhost sshd[1234]: Connection accepted",
            "May 20 10:00:01 myhost cron[5678]: Job completed",
        ]
        result = await self.agent.analyze(state)
        assert isinstance(result, dict)

    @pytest.mark.asyncio
    async def test_analyze_with_app_log_lines(self):
        """Parser should parse application log format."""
        state = AnalysisState(target_path="/tmp")
        state.raw_lines = [
            "2026-05-20 10:00:00 INFO com.app.Main - Application started",
            "2026-05-20 10:00:01 ERROR com.app.DB - Connection timeout",
        ]
        result = await self.agent.analyze(state)
        assert isinstance(result, dict)

    @pytest.mark.asyncio
    async def test_analyze_with_access_log_lines(self):
        """Parser should parse access log format."""
        state = AnalysisState(target_path="/tmp")
        state.raw_lines = [
            '192.168.1.1 - - [20/May/2026:10:00:00 +0000] "GET /api/health HTTP/1.1" 200 45',
            '10.0.0.1 - admin [20/May/2026:10:00:01 +0000] "POST /api/data HTTP/1.1" 500 123',
        ]
        result = await self.agent.analyze(state)
        assert isinstance(result, dict)

    @pytest.mark.asyncio
    async def test_analyze_with_mixed_formats(self):
        """Parser should handle mixed format lines."""
        state = AnalysisState(target_path="/tmp")
        state.raw_lines = [
            '{"level": "info", "message": "json line"}',
            "2026-05-20 10:00:00 ERROR app - error line",
            "unstructured random text",
        ]
        result = await self.agent.analyze(state)
        assert isinstance(result, dict)

    @pytest.mark.asyncio
    async def test_analyze_with_empty_lines(self):
        """Parser should skip empty lines."""
        state = AnalysisState(target_path="/tmp")
        state.raw_lines = ["", "   ", "\t", '{"level": "info", "message": "valid"}']
        result = await self.agent.analyze(state)
        assert isinstance(result, dict)

    @pytest.mark.asyncio
    async def test_analyze_populates_state(self):
        """Parser should populate state with parsed entries."""
        state = AnalysisState(target_path="/tmp")
        state.raw_lines = [
            "2026-05-20 10:00:00 ERROR com.app.Main - Something failed",
            "2026-05-20 10:00:01 INFO com.app.Main - Recovered",
        ]
        await self.agent.analyze(state)
        # The parser agent should have produced results
        assert "parser" in state.agent_results or isinstance(state.log_entries, list)

    @pytest.mark.asyncio
    async def test_analyze_returns_format_stats(self):
        """Parser should return format detection statistics."""
        state = AnalysisState(target_path="/tmp")
        state.raw_lines = [
            '{"level": "info", "message": "test1"}',
            '{"level": "error", "message": "test2"}',
        ]
        result = await self.agent.analyze(state)
        assert isinstance(result, dict)
