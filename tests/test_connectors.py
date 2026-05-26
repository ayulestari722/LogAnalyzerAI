"""Tests for the LogLineParser and FilesystemConnector."""

import os
import pytest
import asyncio
import tempfile
from unittest.mock import patch, MagicMock

from src.connectors.log_parser import LogLineParser, LogFormatDetector
from src.connectors.filesystem import FilesystemConnector


class TestLogLineParser:
    """Tests for LogLineParser."""

    def setup_method(self):
        self.parser = LogLineParser()

    def test_parse_empty_line(self):
        result = self.parser.parse_line("")
        assert result["format"] == "empty"
        assert result["fields"] == {}

    def test_parse_json_line(self):
        line = '{"timestamp": "2026-05-20T10:00:00", "level": "error", "message": "DB connection failed"}'
        result = self.parser.parse_line(line)
        assert result["format"] == "json"
        assert result["fields"]["level"] == "error"
        assert result["fields"]["message"] == "DB connection failed"

    def test_parse_json_with_alternate_keys(self):
        line = '{"time": "2026-05-20T10:00:00", "severity": "warning", "msg": "slow query"}'
        result = self.parser.parse_line(line)
        assert result["format"] == "json"
        assert result["fields"]["timestamp"] == "2026-05-20T10:00:00"
        assert result["fields"]["level"] == "warning"
        assert result["fields"]["message"] == "slow query"

    def test_parse_syslog_line(self):
        line = "May 20 10:00:00 myhost sshd[1234]: Failed password for root from 192.168.1.1"
        result = self.parser.parse_line(line)
        assert result["format"] == "syslog"
        assert result["fields"]["hostname"] == "myhost"
        assert result["fields"]["process"] == "sshd"
        assert "Failed password" in result["fields"]["message"]

    def test_parse_apache_access_line(self):
        line = '192.168.1.1 - admin [20/May/2026:10:00:00 +0000] "GET /index.html HTTP/1.1" 200 1234'
        result = self.parser.parse_line(line)
        assert result["format"] in ("apache", "nginx", "clf")
        assert result["fields"]["ip"] == "192.168.1.1"
        assert result["fields"]["method"] == "GET"
        assert result["fields"]["status"] == 200

    def test_parse_nginx_access_line(self):
        line = '10.0.0.1 - - [20/May/2026:10:00:00 +0000] "POST /api/data HTTP/1.1" 500 89 "-" "curl/7.68" 0.250'
        result = self.parser.parse_line(line)
        assert result["format"] in ("apache", "nginx", "clf")
        assert result["fields"]["status"] == 500
        assert result["severity"] == "error"

    def test_parse_app_log_line(self):
        line = "2026-05-20 10:00:00 ERROR com.app.Service - Database connection timeout"
        result = self.parser.parse_line(line)
        assert result["format"] == "app_log"
        assert result["fields"]["level"] == "ERROR"
        assert "Database connection timeout" in result["fields"]["message"]

    def test_parse_unstructured_line(self):
        line = "Something happened that doesn't match any format"
        result = self.parser.parse_line(line)
        assert result["format"] == "unstructured"
        assert result["fields"]["message"] == line

    def test_severity_detection_from_message(self):
        error_line = "2026-05-20 10:00:00 ERROR Something failed"
        result = self.parser.parse_line(error_line)
        assert result["severity"] == "error"

    def test_parse_with_expected_format(self):
        line = '{"level": "info", "message": "test"}'
        result = self.parser.parse_line(line, expected_format="json")
        assert result["format"] == "json"


class TestLogFormatDetector:
    """Tests for LogFormatDetector."""

    def setup_method(self):
        self.detector = LogFormatDetector()

    def test_detect_json_format(self):
        lines = [
            '{"level": "info", "message": "start"}',
            '{"level": "error", "message": "fail"}',
            '{"level": "debug", "message": "trace"}',
        ]
        result = self.detector.detect_format(lines)
        assert result["format"] == "json"
        assert result["confidence"] > 0.5

    def test_detect_syslog_format(self):
        lines = [
            "May 20 10:00:00 host1 sshd[100]: session opened",
            "May 20 10:00:01 host1 cron[200]: job started",
            "May 20 10:00:02 host1 kernel: disk error",
        ]
        result = self.detector.detect_format(lines)
        assert result["format"] == "syslog"

    def test_detect_empty_lines(self):
        result = self.detector.detect_format([])
        assert result["format"] == "unknown"
        assert result["confidence"] == 0.0

    def test_detect_unstructured(self):
        lines = ["random text", "no pattern here", "just words"]
        result = self.detector.detect_format(lines)
        assert result["format"] == "unstructured"


class TestFilesystemConnector:
    """Tests for FilesystemConnector."""

    def test_init_defaults(self):
        connector = FilesystemConnector(paths=["/tmp"])
        assert connector.paths == ["/tmp"]
        assert connector.recursive is True
        assert "*.log" in connector.patterns

    def test_discover_files_with_real_directory(self, tmp_path):
        # Create test files
        log_file = tmp_path / "test.log"
        log_file.write_text("line1\nline2\n")
        json_file = tmp_path / "data.json"
        json_file.write_text('{"key": "value"}\n')
        hidden_file = tmp_path / ".hidden.log"
        hidden_file.write_text("hidden\n")

        connector = FilesystemConnector(paths=[str(tmp_path)])
        files = connector.discover_files()

        assert str(log_file) in files
        assert str(json_file) in files
        # Hidden files should be excluded
        assert str(hidden_file) not in files

    def test_discover_files_single_file(self, tmp_path):
        log_file = tmp_path / "single.log"
        log_file.write_text("content\n")

        connector = FilesystemConnector(paths=[str(log_file)])
        files = connector.discover_files()
        assert str(log_file) in files

    def test_discover_files_empty_directory(self, tmp_path):
        connector = FilesystemConnector(paths=[str(tmp_path)])
        files = connector.discover_files()
        assert files == []

    @pytest.mark.asyncio
    async def test_read_file(self, tmp_path):
        log_file = tmp_path / "read_test.log"
        log_file.write_text("line1\nline2\nline3\n")

        connector = FilesystemConnector(paths=[str(tmp_path)])
        lines = await connector.read_file(str(log_file))
        assert len(lines) == 3
        assert lines[0] == "line1"

    @pytest.mark.asyncio
    async def test_read_file_not_found(self):
        connector = FilesystemConnector(paths=["/tmp"])
        with pytest.raises(FileNotFoundError):
            await connector.read_file("/nonexistent/file.log")

    @pytest.mark.asyncio
    async def test_read_file_too_large(self, tmp_path):
        large_file = tmp_path / "large.log"
        large_file.write_text("x" * 100)

        connector = FilesystemConnector(paths=[str(tmp_path)], max_file_size_mb=0.00001)
        with pytest.raises(ValueError, match="File too large"):
            await connector.read_file(str(large_file))

    def test_is_valid_file_skips_binary(self, tmp_path):
        gz_file = tmp_path / "archive.gz"
        gz_file.write_text("fake gz content")

        connector = FilesystemConnector(paths=[str(tmp_path)])
        assert connector._is_valid_file(str(gz_file)) is False

    def test_get_file_info(self, tmp_path):
        log_file = tmp_path / "info_test.log"
        log_file.write_text("some content\n")

        connector = FilesystemConnector(paths=[str(tmp_path)])
        info = connector.get_file_info(str(log_file))
        assert "size_bytes" in info
        assert info["size_bytes"] > 0
