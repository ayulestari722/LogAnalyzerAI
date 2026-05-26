"""Tests for utility modules."""

import pytest
import os
import tempfile
from pathlib import Path

from src.utils.config import load_config, get_default_config, validate_config
from src.utils.severity import Severity, SeverityScorer
from src.utils.serializers import JSONSerializer, MarkdownSerializer, SARIFSerializer, get_serializer
from src.utils.metrics import MetricsCollector
from src.utils.logger import setup_logger, get_logger


class TestConfig:
    """Test configuration loading."""

    def test_default_config_has_required_keys(self):
        config = get_default_config()
        assert "orchestrator" in config
        assert "agents" in config
        assert "output" in config
        assert "severity" in config

    def test_default_timeout(self):
        config = get_default_config()
        assert config["orchestrator"]["timeout_per_agent"] == 30.0

    def test_load_config_no_file(self):
        config = load_config(None)
        assert config is not None
        assert "orchestrator" in config

    def test_load_config_from_file(self):
        config = load_config("config/default.yaml")
        assert config is not None
        assert config["orchestrator"]["timeout_per_agent"] == 30.0

    def test_validate_config_valid(self):
        config = get_default_config()
        warnings = validate_config(config)
        assert len(warnings) == 0

    def test_validate_config_bad_timeout(self):
        config = get_default_config()
        config["orchestrator"]["timeout_per_agent"] = -1
        warnings = validate_config(config)
        assert any("timeout" in w for w in warnings)

    def test_validate_config_bad_format(self):
        config = get_default_config()
        config["output"]["format"] = "xml"
        warnings = validate_config(config)
        assert any("format" in w for w in warnings)


class TestSeverity:
    """Test severity scoring."""

    def test_from_string_error(self):
        assert Severity.from_string("error") == Severity.HIGH

    def test_from_string_warning(self):
        assert Severity.from_string("warning") == Severity.MEDIUM

    def test_from_string_critical(self):
        assert Severity.from_string("critical") == Severity.CRITICAL

    def test_from_string_unknown(self):
        assert Severity.from_string("unknown") == Severity.INFO

    def test_scorer_empty_findings(self):
        scorer = SeverityScorer()
        assert scorer.score_findings([]) == 0.0

    def test_scorer_all_critical(self):
        scorer = SeverityScorer()
        findings = [{"severity": "critical"}] * 5
        score = scorer.score_findings(findings)
        assert score == 100.0

    def test_scorer_mixed(self):
        scorer = SeverityScorer()
        findings = [
            {"severity": "critical"},
            {"severity": "high"},
            {"severity": "info"},
        ]
        score = scorer.score_findings(findings)
        assert 0 < score < 100

    def test_classify_overall(self):
        scorer = SeverityScorer()
        assert scorer.classify_overall(85) == Severity.CRITICAL
        assert scorer.classify_overall(65) == Severity.HIGH
        assert scorer.classify_overall(45) == Severity.MEDIUM
        assert scorer.classify_overall(25) == Severity.LOW
        assert scorer.classify_overall(10) == Severity.INFO

    def test_exceeds_threshold(self):
        scorer = SeverityScorer(threshold=50.0)
        assert scorer.exceeds_threshold(60) is True
        assert scorer.exceeds_threshold(40) is False


class TestSerializers:
    """Test output serializers."""

    def test_json_serializer(self):
        s = JSONSerializer()
        output = s.serialize({"summary": {"score": 42}, "findings": [], "metrics": {}})
        assert '"score": 42' in output
        assert s.get_extension() == "json"

    def test_markdown_serializer(self):
        s = MarkdownSerializer()
        output = s.serialize({"summary": {"score": 42, "verdict": "Medium", "files_analyzed": 3, "total_entries": 100, "duration": 1.5, "severity_distribution": {}}, "findings": [], "metrics": {}, "agent_results": {}})
        assert "LogAnalyzerAI" in output
        assert s.get_extension() == "md"

    def test_sarif_serializer(self):
        s = SARIFSerializer()
        output = s.serialize({"findings": [{"rule_id": "test", "severity": "high", "message": "Test finding"}]})
        assert "sarif" in output.lower() or "2.1.0" in output
        assert s.get_extension() == "sarif"

    def test_get_serializer_factory(self):
        assert isinstance(get_serializer("json"), JSONSerializer)
        assert isinstance(get_serializer("markdown"), MarkdownSerializer)
        assert isinstance(get_serializer("sarif"), SARIFSerializer)

    def test_get_serializer_invalid(self):
        with pytest.raises(ValueError):
            get_serializer("xml")


class TestMetricsCollector:
    """Test metrics collection."""

    def test_counter(self):
        m = MetricsCollector()
        m.increment("test_counter", 5)
        assert m.get_counter("test_counter") == 5
        m.increment("test_counter", 3)
        assert m.get_counter("test_counter") == 8

    def test_gauge(self):
        m = MetricsCollector()
        m.set_gauge("cpu", 42.5)
        assert m.get_gauge("cpu") == 42.5

    def test_timer(self):
        import time
        m = MetricsCollector()
        m.start_timer("test_op")
        time.sleep(0.01)
        duration = m.stop_timer("test_op")
        assert duration > 0
        stats = m.get_timing_stats("test_op")
        assert stats["count"] == 1

    def test_summary(self):
        m = MetricsCollector()
        m.increment("x", 1)
        m.set_gauge("y", 2.0)
        summary = m.get_summary()
        assert "counters" in summary
        assert "gauges" in summary

    def test_reset(self):
        m = MetricsCollector()
        m.increment("x", 10)
        m.reset()
        assert m.get_counter("x") == 0


class TestLogger:
    """Test logger setup."""

    def test_setup_logger(self):
        logger = setup_logger("test_logger", level="DEBUG")
        assert logger is not None
        assert logger.name == "test_logger"

    def test_get_logger(self):
        logger = get_logger("another_test")
        assert logger is not None
