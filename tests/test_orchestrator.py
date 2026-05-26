"""Tests for AsyncOrchestrator."""

import asyncio
import pytest
from unittest.mock import patch, AsyncMock

from src.orchestrator import AsyncOrchestrator
from src.models.analysis_state import AnalysisState
from src.models.log_entry import LogEntry, LogBatch, Severity


@pytest.fixture
def orchestrator():
    """Create orchestrator with default config."""
    return AsyncOrchestrator()


@pytest.fixture
def custom_orchestrator():
    """Create orchestrator with custom config."""
    config = {
        "orchestrator": {"timeout_per_agent": 5.0, "max_concurrent_agents": 3},
        "agents": {
            "parser": {"enabled": True},
            "anomaly": {"enabled": True, "z_score_threshold": 2.0},
            "pattern": {"enabled": True},
            "correlation": {"enabled": True},
            "alert": {"enabled": True},
            "metrics": {"enabled": True},
            "summary": {"enabled": True},
        },
        "output": {"format": "json"},
        "severity": {"weights": {"critical": 10, "high": 7, "medium": 4, "low": 2, "info": 1}, "score_threshold": 50},
        "logging": {"level": "ERROR"},
    }
    return AsyncOrchestrator(config=config)


class TestOrchestratorInit:
    """Test orchestrator initialization."""

    def test_default_init(self, orchestrator):
        assert orchestrator is not None
        assert len(orchestrator._agents) == 6  # 6 parallel agents

    def test_summary_agent_initialized(self, orchestrator):
        assert orchestrator._summary_agent is not None
        assert orchestrator._summary_agent.name == "summary"

    def test_custom_config(self, custom_orchestrator):
        assert custom_orchestrator.config["orchestrator"]["timeout_per_agent"] == 5.0

    def test_repr(self, orchestrator):
        repr_str = repr(orchestrator)
        assert "AsyncOrchestrator" in repr_str
        assert "parser" in repr_str

    def test_disabled_agent(self):
        config = {
            "orchestrator": {"timeout_per_agent": 30.0, "max_concurrent_agents": 6},
            "agents": {
                "parser": {"enabled": False},
                "anomaly": {"enabled": True},
                "pattern": {"enabled": True},
                "correlation": {"enabled": True},
                "alert": {"enabled": True},
                "metrics": {"enabled": True},
                "summary": {"enabled": True},
            },
            "output": {"format": "json"},
            "severity": {"weights": {"critical": 10, "high": 7, "medium": 4, "low": 2, "info": 1}, "score_threshold": 50},
            "logging": {"level": "ERROR"},
        }
        o = AsyncOrchestrator(config=config)
        agent_names = [a.name for a in o._agents]
        assert "parser" not in agent_names


class TestOrchestratorPipeline:
    """Test pipeline execution."""

    @pytest.mark.asyncio
    async def test_run_pipeline_sample_logs(self, orchestrator):
        results = await orchestrator.run_pipeline(
            target_path="./examples/sample_logs",
            output_format="json",
            output_file="/tmp/test_output.json",
        )
        assert "summary" in results
        assert results["summary"]["files_analyzed"] == 3
        assert results["summary"]["total_entries"] > 0

    @pytest.mark.asyncio
    async def test_run_pipeline_empty_dir(self, orchestrator, tmp_path):
        empty_dir = tmp_path / "empty"
        empty_dir.mkdir()
        results = await orchestrator.run_pipeline(
            target_path=str(empty_dir),
            output_format="json",
        )
        assert results["summary"]["verdict"] == "No data"

    @pytest.mark.asyncio
    async def test_run_pipeline_markdown_format(self, orchestrator):
        results = await orchestrator.run_pipeline(
            target_path="./examples/sample_logs",
            output_format="markdown",
            output_file="/tmp/test_output.md",
        )
        assert results["summary"]["files_analyzed"] == 3

    @pytest.mark.asyncio
    async def test_run_pipeline_sarif_format(self, orchestrator):
        results = await orchestrator.run_pipeline(
            target_path="./examples/sample_logs",
            output_format="sarif",
            output_file="/tmp/test_output.sarif",
        )
        assert "summary" in results

    @pytest.mark.asyncio
    async def test_pipeline_metrics_collected(self, orchestrator):
        results = await orchestrator.run_pipeline(
            target_path="./examples/sample_logs",
            output_format="json",
            output_file="/tmp/test_metrics.json",
        )
        assert "metrics" in results
        assert "total_duration_seconds" in results["metrics"]

    @pytest.mark.asyncio
    async def test_agent_results_tracked(self, orchestrator):
        results = await orchestrator.run_pipeline(
            target_path="./examples/sample_logs",
            output_format="json",
            output_file="/tmp/test_agents.json",
        )
        assert "agent_results" in results
        for agent_name, result in results["agent_results"].items():
            assert "status" in result
            assert "duration" in result
