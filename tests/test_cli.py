"""Tests for CLI commands."""

import pytest
from click.testing import CliRunner

from src.cli import cli


@pytest.fixture
def runner():
    return CliRunner()


class TestCLI:
    """Test CLI commands."""

    def test_cli_help(self, runner):
        result = runner.invoke(cli, ["--help"])
        assert result.exit_code == 0
        assert "LogAnalyzerAI" in result.output

    def test_run_command_help(self, runner):
        result = runner.invoke(cli, ["run", "--help"])
        assert result.exit_code == 0
        assert "TARGET" in result.output

    def test_run_sample_logs(self, runner):
        result = runner.invoke(cli, ["run", "./examples/sample_logs", "--format", "json", "-o", "/tmp/cli_test.json"])
        assert result.exit_code == 0

    def test_info_command(self, runner):
        result = runner.invoke(cli, ["info"])
        assert result.exit_code == 0
        assert "LogAnalyzerAI" in result.output
        assert "Timeout" in result.output or "timeout" in result.output

    def test_run_nonexistent_path(self, runner):
        result = runner.invoke(cli, ["run", "/nonexistent/path"])
        assert result.exit_code != 0

    def test_report_command(self, runner, tmp_path):
        output_file = str(tmp_path / "report.json")
        result = runner.invoke(cli, ["report", "./examples/sample_logs", "-f", "json", "-o", output_file])
        assert result.exit_code == 0
