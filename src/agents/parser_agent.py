"""
ParserAgent — Parses multi-format logs: JSON, syslog, Apache, nginx.

Detects log format automatically and converts raw lines into structured
LogEntry objects for downstream analysis.
"""

import json
import re
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

from src.agents.base import BaseAgent
from src.models.analysis_state import AnalysisState
from src.models.log_entry import LogEntry, LogBatch, Severity


# Common log format patterns
SYSLOG_PATTERN = re.compile(
    r"^(?P<timestamp>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+"
    r"(?P<hostname>\S+)\s+"
    r"(?P<process>\S+?)(?:\[(?P<pid>\d+)\])?\s*:\s*"
    r"(?P<message>.+)$"
)

APACHE_COMBINED_PATTERN = re.compile(
    r'^(?P<ip>\S+)\s+\S+\s+(?P<user>\S+)\s+'
    r'\[(?P<timestamp>[^\]]+)\]\s+'
    r'"(?P<method>\S+)\s+(?P<path>\S+)\s+(?P<protocol>\S+)"\s+'
    r'(?P<status>\d{3})\s+(?P<size>\d+|-)\s*'
    r'(?:"(?P<referer>[^"]*)")?\s*(?:"(?P<user_agent>[^"]*)")?'
)

NGINX_PATTERN = re.compile(
    r'^(?P<ip>\S+)\s+-\s+(?P<user>\S+)\s+'
    r'\[(?P<timestamp>[^\]]+)\]\s+'
    r'"(?P<method>\S+)\s+(?P<path>\S+)\s+(?P<protocol>\S+)"\s+'
    r'(?P<status>\d{3})\s+(?P<size>\d+)\s+'
    r'"(?P<referer>[^"]*)"\s+"(?P<user_agent>[^"]*)"'
    r'(?:\s+(?P<request_time>[\d.]+))?'
)

APP_LOG_PATTERN = re.compile(
    r"^(?P<timestamp>\d{4}-\d{2}-\d{2}[\sT]\d{2}:\d{2}:\d{2}(?:[.,]\d{3})?)\s+"
    r"(?:\[(?P<thread>[^\]]+)\]\s+)?"
    r"(?P<level>\w+)\s+"
    r"(?:(?P<logger>\S+)\s*[-:]\s*)?"
    r"(?P<message>.+)$"
)

TIMESTAMP_FORMATS = [
    "%Y-%m-%d %H:%M:%S,%f",
    "%Y-%m-%d %H:%M:%S.%f",
    "%Y-%m-%dT%H:%M:%S.%f",
    "%Y-%m-%dT%H:%M:%S",
    "%Y-%m-%d %H:%M:%S",
    "%d/%b/%Y:%H:%M:%S %z",
    "%d/%b/%Y:%H:%M:%S",
]

SYSLOG_TIMESTAMP_FORMATS = [
    "%b %d %H:%M:%S",
    "%b  %d %H:%M:%S",
]

LEVEL_TO_SEVERITY = {
    "TRACE": Severity.DEBUG,
    "DEBUG": Severity.DEBUG,
    "INFO": Severity.INFO,
    "NOTICE": Severity.INFO,
    "WARN": Severity.WARNING,
    "WARNING": Severity.WARNING,
    "ERROR": Severity.ERROR,
    "ERR": Severity.ERROR,
    "CRITICAL": Severity.CRITICAL,
    "CRIT": Severity.CRITICAL,
    "FATAL": Severity.CRITICAL,
    "EMERGENCY": Severity.CRITICAL,
    "EMERG": Severity.CRITICAL,
    "ALERT": Severity.CRITICAL,
}


class ParserAgent(BaseAgent):
    """Agent responsible for parsing raw log lines into structured LogEntry objects.

    Supports automatic format detection for JSON, syslog, Apache combined,
    nginx, and generic application log formats.
    """

    def __init__(self, config: Optional[Dict[str, Any]] = None) -> None:
        super().__init__(name="parser", config=config)
        self._format_stats: Dict[str, int] = {}
        self._parse_errors: List[Dict[str, Any]] = []

    async def analyze(self, state: AnalysisState) -> Dict[str, Any]:
        """Parse all raw log lines in the state into structured LogEntry objects.

        Args:
            state: Analysis state containing raw_lines to parse.

        Returns:
            Dictionary with parsed entries count, format statistics, and errors.
        """
        raw_lines = state.raw_lines
        parsed_entries: List[LogEntry] = []
        self._format_stats = {}
        self._parse_errors = []

        for idx, line in enumerate(raw_lines):
            stripped = line.strip()
            if not stripped:
                continue

            entry, fmt = self._parse_line(stripped, idx, state.source_file)
            if entry is not None:
                parsed_entries.append(entry)
                self._format_stats[fmt] = self._format_stats.get(fmt, 0) + 1
            else:
                self._parse_errors.append({
                    "line_number": idx + 1,
                    "content": stripped[:200],
                    "reason": "no_matching_format",
                })

        state.log_entries = parsed_entries
        state.log_batch = LogBatch(
            entries=parsed_entries,
            source=state.source_file or "unknown",
            total_lines=len(raw_lines),
            parsed_lines=len(parsed_entries),
        )

        return {
            "total_lines": len(raw_lines),
            "parsed_entries": len(parsed_entries),
            "parse_errors": len(self._parse_errors),
            "format_distribution": dict(self._format_stats),
            "error_details": self._parse_errors[:20],
        }

    def _parse_line(
        self, line: str, line_number: int, source: Optional[str]
    ) -> Tuple[Optional[LogEntry], str]:
        """Attempt to parse a single log line using all known formats.

        Returns:
            Tuple of (LogEntry or None, format_name).
        """
        # Try JSON first
        if line.startswith("{"):
            entry = self._parse_json(line, line_number, source)
            if entry is not None:
                return entry, "json"

        # Try application log format
        match = APP_LOG_PATTERN.match(line)
        if match:
            entry = self._parse_app_log(match, line_number, source)
            if entry is not None:
                return entry, "app_log"

        # Try nginx format
        match = NGINX_PATTERN.match(line)
        if match:
            entry = self._parse_nginx(match, line_number, source)
            if entry is not None:
                return entry, "nginx"

        # Try Apache combined format
        match = APACHE_COMBINED_PATTERN.match(line)
        if match:
            entry = self._parse_apache(match, line_number, source)
            if entry is not None:
                return entry, "apache"

        # Try syslog format
        match = SYSLOG_PATTERN.match(line)
        if match:
            entry = self._parse_syslog(match, line_number, source)
            if entry is not None:
                return entry, "syslog"

        # Fallback: treat as unstructured message
        entry = LogEntry(
            timestamp=None,
            severity=Severity.INFO,
            message=line,
            source=source or "unknown",
            line_number=line_number + 1,
            raw=line,
            metadata={},
        )
        return entry, "unstructured"

    def _parse_json(
        self, line: str, line_number: int, source: Optional[str]
    ) -> Optional[LogEntry]:
        """Parse a JSON-formatted log line."""
        try:
            data = json.loads(line)
        except json.JSONDecodeError:
            return None

        timestamp = self._extract_timestamp_from_dict(data)
        level_str = str(
            data.get("level", data.get("severity", data.get("log_level", "INFO")))
        ).upper()
        severity = LEVEL_TO_SEVERITY.get(level_str, Severity.INFO)
        message = data.get("message", data.get("msg", data.get("text", str(data))))

        metadata = {
            k: v for k, v in data.items()
            if k not in ("timestamp", "time", "@timestamp", "level", "severity",
                         "log_level", "message", "msg", "text")
        }

        return LogEntry(
            timestamp=timestamp,
            severity=severity,
            message=str(message),
            source=source or "unknown",
            line_number=line_number + 1,
            raw=line,
            metadata=metadata,
        )

    def _parse_app_log(
        self, match: re.Match, line_number: int, source: Optional[str]
    ) -> Optional[LogEntry]:
        """Parse an application log format line."""
        groups = match.groupdict()
        timestamp = self._parse_timestamp(groups["timestamp"])
        level_str = groups["level"].upper()
        severity = LEVEL_TO_SEVERITY.get(level_str, Severity.INFO)

        metadata: Dict[str, Any] = {}
        if groups.get("thread"):
            metadata["thread"] = groups["thread"]
        if groups.get("logger"):
            metadata["logger"] = groups["logger"]

        return LogEntry(
            timestamp=timestamp,
            severity=severity,
            message=groups["message"],
            source=source or "unknown",
            line_number=line_number + 1,
            raw=match.string,
            metadata=metadata,
        )

    def _parse_nginx(
        self, match: re.Match, line_number: int, source: Optional[str]
    ) -> Optional[LogEntry]:
        """Parse an nginx access log line."""
        groups = match.groupdict()
        timestamp = self._parse_timestamp(groups["timestamp"])
        status_code = int(groups["status"])
        severity = self._severity_from_status(status_code)

        message = f"{groups['method']} {groups['path']} {status_code}"
        metadata = {
            "ip": groups["ip"],
            "user": groups["user"],
            "method": groups["method"],
            "path": groups["path"],
            "protocol": groups["protocol"],
            "status": status_code,
            "size": int(groups["size"]) if groups["size"] != "-" else 0,
            "referer": groups.get("referer", ""),
            "user_agent": groups.get("user_agent", ""),
            "format": "nginx",
        }
        if groups.get("request_time"):
            metadata["request_time"] = float(groups["request_time"])

        return LogEntry(
            timestamp=timestamp,
            severity=severity,
            message=message,
            source=source or "unknown",
            line_number=line_number + 1,
            raw=match.string,
            metadata=metadata,
        )

    def _parse_apache(
        self, match: re.Match, line_number: int, source: Optional[str]
    ) -> Optional[LogEntry]:
        """Parse an Apache combined log format line."""
        groups = match.groupdict()
        timestamp = self._parse_timestamp(groups["timestamp"])
        status_code = int(groups["status"])
        severity = self._severity_from_status(status_code)

        message = f"{groups['method']} {groups['path']} {status_code}"
        metadata = {
            "ip": groups["ip"],
            "user": groups["user"],
            "method": groups["method"],
            "path": groups["path"],
            "protocol": groups["protocol"],
            "status": status_code,
            "size": int(groups["size"]) if groups["size"] != "-" else 0,
            "referer": groups.get("referer", ""),
            "user_agent": groups.get("user_agent", ""),
            "format": "apache",
        }

        return LogEntry(
            timestamp=timestamp,
            severity=severity,
            message=message,
            source=source or "unknown",
            line_number=line_number + 1,
            raw=match.string,
            metadata=metadata,
        )

    def _parse_syslog(
        self, match: re.Match, line_number: int, source: Optional[str]
    ) -> Optional[LogEntry]:
        """Parse a syslog format line."""
        groups = match.groupdict()
        timestamp = self._parse_syslog_timestamp(groups["timestamp"])
        message = groups["message"]

        # Attempt to extract severity from message content
        severity = Severity.INFO
        msg_upper = message.upper()
        for level_key, sev in LEVEL_TO_SEVERITY.items():
            if level_key in msg_upper:
                severity = sev
                break

        metadata = {
            "hostname": groups["hostname"],
            "process": groups["process"],
            "format": "syslog",
        }
        if groups.get("pid"):
            metadata["pid"] = int(groups["pid"])

        return LogEntry(
            timestamp=timestamp,
            severity=severity,
            message=message,
            source=source or "unknown",
            line_number=line_number + 1,
            raw=match.string,
            metadata=metadata,
        )

    def _parse_timestamp(self, ts_str: str) -> Optional[datetime]:
        """Try multiple timestamp formats to parse a timestamp string."""
        for fmt in TIMESTAMP_FORMATS:
            try:
                return datetime.strptime(ts_str.strip(), fmt)
            except ValueError:
                continue
        return None

    def _parse_syslog_timestamp(self, ts_str: str) -> Optional[datetime]:
        """Parse syslog-style timestamps (no year)."""
        for fmt in SYSLOG_TIMESTAMP_FORMATS:
            try:
                dt = datetime.strptime(ts_str.strip(), fmt)
                return dt.replace(year=datetime.now().year)
            except ValueError:
                continue
        return None

    def _extract_timestamp_from_dict(self, data: Dict[str, Any]) -> Optional[datetime]:
        """Extract and parse timestamp from a JSON log dictionary."""
        for key in ("timestamp", "time", "@timestamp", "ts", "datetime"):
            if key in data:
                val = data[key]
                if isinstance(val, (int, float)):
                    try:
                        return datetime.fromtimestamp(val)
                    except (OSError, ValueError):
                        continue
                elif isinstance(val, str):
                    parsed = self._parse_timestamp(val)
                    if parsed:
                        return parsed
        return None

    @staticmethod
    def _severity_from_status(status_code: int) -> Severity:
        """Map HTTP status code to severity level."""
        if status_code < 300:
            return Severity.INFO
        elif status_code < 400:
            return Severity.INFO
        elif status_code < 500:
            return Severity.WARNING
        else:
            return Severity.ERROR
