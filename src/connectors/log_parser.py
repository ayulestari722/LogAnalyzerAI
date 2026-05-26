"""
LogFormatDetector and LineParser — Low-level log format detection and line parsing.

Provides format auto-detection by sampling lines and parsing individual
log lines according to detected or specified formats.
"""

import json
import re
from collections import Counter
from typing import Any, Dict, List, Optional, Tuple

from src.models.log_entry import Severity


# Format signature patterns for detection
FORMAT_SIGNATURES = {
    "json": re.compile(r"^\s*\{.*\}\s*$"),
    "syslog": re.compile(
        r"^\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+\S+\s+\S+"
    ),
    "nginx": re.compile(
        r'^\S+\s+-\s+\S+\s+\[\d{2}/\w{3}/\d{4}:\d{2}:\d{2}:\d{2}\s+[+-]\d{4}\]\s+"'
    ),
    "apache": re.compile(
        r'^\S+\s+\S+\s+\S+\s+\[\d{2}/\w{3}/\d{4}:\d{2}:\d{2}:\d{2}\s+[+-]\d{4}\]\s+"'
    ),
    "app_log": re.compile(
        r"^\d{4}-\d{2}-\d{2}[\sT]\d{2}:\d{2}:\d{2}"
    ),
    "clf": re.compile(
        r'^\S+\s+\S+\s+\S+\s+\[.+\]\s+"\w+\s+\S+\s+\S+"\s+\d{3}\s+\d+'
    ),
}

# Severity detection patterns for unstructured logs
SEVERITY_PATTERNS = [
    (re.compile(r"\b(?:FATAL|EMERG(?:ENCY)?|ALERT)\b", re.IGNORECASE), Severity.CRITICAL),
    (re.compile(r"\b(?:CRIT(?:ICAL)?)\b", re.IGNORECASE), Severity.CRITICAL),
    (re.compile(r"\b(?:ERR(?:OR)?)\b", re.IGNORECASE), Severity.ERROR),
    (re.compile(r"\b(?:WARN(?:ING)?)\b", re.IGNORECASE), Severity.WARNING),
    (re.compile(r"\b(?:INFO(?:RMATION)?|NOTICE)\b", re.IGNORECASE), Severity.INFO),
    (re.compile(r"\b(?:DEBUG|TRACE)\b", re.IGNORECASE), Severity.DEBUG),
]


class LogFormatDetector:
    """Detects the format of log files by sampling lines.

    Uses pattern matching and heuristics to determine the most likely
    format of a log file or stream.
    """

    def __init__(self, sample_size: int = 20) -> None:
        """Initialize the format detector.

        Args:
            sample_size: Number of lines to sample for detection.
        """
        self.sample_size = sample_size

    def detect_format(self, lines: List[str]) -> Dict[str, Any]:
        """Detect the format of log lines.

        Args:
            lines: Sample of log lines to analyze.

        Returns:
            Dictionary with detected format, confidence, and metadata.
        """
        if not lines:
            return {
                "format": "unknown",
                "confidence": 0.0,
                "details": {},
            }

        # Sample lines for detection
        sample = lines[:self.sample_size]
        non_empty = [line.strip() for line in sample if line.strip()]

        if not non_empty:
            return {
                "format": "unknown",
                "confidence": 0.0,
                "details": {},
            }

        # Score each format
        format_scores: Dict[str, int] = Counter()
        for line in non_empty:
            for fmt_name, pattern in FORMAT_SIGNATURES.items():
                if pattern.match(line):
                    format_scores[fmt_name] += 1

        if not format_scores:
            return {
                "format": "unstructured",
                "confidence": 0.5,
                "details": {"reason": "no_matching_patterns"},
            }

        # Determine winner
        total_lines = len(non_empty)
        best_format, best_count = format_scores.most_common(1)[0]
        confidence = best_count / total_lines

        # Resolve nginx vs apache ambiguity
        if "nginx" in format_scores and "apache" in format_scores:
            # Check for request_time field (nginx-specific)
            has_request_time = any(
                re.search(r'"\s+[\d.]+$', line) for line in non_empty
            )
            if has_request_time:
                best_format = "nginx"
            else:
                best_format = "apache"

        return {
            "format": best_format,
            "confidence": round(confidence, 3),
            "details": {
                "scores": dict(format_scores),
                "sample_size": total_lines,
                "all_formats_detected": list(format_scores.keys()),
            },
        }

    def detect_multiformat(self, lines: List[str]) -> List[Dict[str, Any]]:
        """Detect if a file contains multiple formats (e.g., mixed sources).

        Returns:
            List of format segments with line ranges.
        """
        segments: List[Dict[str, Any]] = []
        current_format: Optional[str] = None
        segment_start = 0

        for i, line in enumerate(lines):
            stripped = line.strip()
            if not stripped:
                continue

            detected = None
            for fmt_name, pattern in FORMAT_SIGNATURES.items():
                if pattern.match(stripped):
                    detected = fmt_name
                    break

            if detected is None:
                detected = "unstructured"

            if detected != current_format:
                if current_format is not None:
                    segments.append({
                        "format": current_format,
                        "start_line": segment_start,
                        "end_line": i - 1,
                        "line_count": i - segment_start,
                    })
                current_format = detected
                segment_start = i

        # Final segment
        if current_format is not None:
            segments.append({
                "format": current_format,
                "start_line": segment_start,
                "end_line": len(lines) - 1,
                "line_count": len(lines) - segment_start,
            })

        return segments


class LogLineParser:
    """Low-level parser for individual log lines.

    Provides format-specific parsing without the full agent infrastructure.
    Useful for connectors and pre-processing stages.
    """

    def __init__(self) -> None:
        """Initialize the line parser."""
        self._json_fields_map: Dict[str, str] = {
            "msg": "message",
            "message": "message",
            "text": "message",
            "level": "level",
            "severity": "level",
            "log_level": "level",
            "timestamp": "timestamp",
            "time": "timestamp",
            "@timestamp": "timestamp",
            "ts": "timestamp",
        }

    def parse_line(
        self, line: str, expected_format: Optional[str] = None, source: str = ""
    ) -> Dict[str, Any]:
        """Parse a single log line into structured fields.

        Args:
            line: Raw log line to parse.
            expected_format: Expected format hint (skips detection if provided).
            source: Source file path or identifier.

        Returns:
            Dictionary with parsed fields.
        """
        stripped = line.strip()
        if not stripped:
            return {"raw": line, "format": "empty", "fields": {}}

        # Try expected format first
        if expected_format:
            result = self._parse_by_format(stripped, expected_format)
            if result:
                return result

        # Auto-detect and parse
        for fmt_name, pattern in FORMAT_SIGNATURES.items():
            if pattern.match(stripped):
                result = self._parse_by_format(stripped, fmt_name)
                if result:
                    return result

        # Fallback: extract what we can
        return self._parse_unstructured(stripped)

    def _parse_by_format(
        self, line: str, fmt: str
    ) -> Optional[Dict[str, Any]]:
        """Parse a line according to a specific format."""
        parsers = {
            "json": self._parse_json_line,
            "syslog": self._parse_syslog_line,
            "nginx": self._parse_access_line,
            "apache": self._parse_access_line,
            "app_log": self._parse_app_line,
            "clf": self._parse_access_line,
        }

        parser = parsers.get(fmt)
        if parser:
            return parser(line, fmt)
        return None

    def _parse_json_line(
        self, line: str, fmt: str
    ) -> Optional[Dict[str, Any]]:
        """Parse a JSON log line."""
        try:
            data = json.loads(line)
        except json.JSONDecodeError:
            return None

        fields: Dict[str, Any] = {}
        for json_key, field_name in self._json_fields_map.items():
            if json_key in data:
                fields[field_name] = data[json_key]

        # Remaining fields as metadata
        metadata = {
            k: v for k, v in data.items()
            if k not in self._json_fields_map
        }

        severity = self._detect_severity(
            str(fields.get("level", "info"))
        )

        return {
            "raw": line,
            "format": "json",
            "fields": fields,
            "metadata": metadata,
            "severity": severity.value,
        }

    def _parse_syslog_line(
        self, line: str, fmt: str
    ) -> Optional[Dict[str, Any]]:
        """Parse a syslog format line."""
        pattern = re.compile(
            r"^(?P<timestamp>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+"
            r"(?P<hostname>\S+)\s+"
            r"(?P<process>\S+?)(?:\[(?P<pid>\d+)\])?\s*:\s*"
            r"(?P<message>.+)$"
        )
        match = pattern.match(line)
        if not match:
            return None

        groups = match.groupdict()
        severity = self._detect_severity(groups["message"])

        return {
            "raw": line,
            "format": "syslog",
            "fields": {
                "timestamp": groups["timestamp"],
                "hostname": groups["hostname"],
                "process": groups["process"],
                "pid": groups.get("pid"),
                "message": groups["message"],
            },
            "metadata": {},
            "severity": severity.value,
        }

    def _parse_access_line(
        self, line: str, fmt: str
    ) -> Optional[Dict[str, Any]]:
        """Parse an access log line (nginx/apache/CLF)."""
        pattern = re.compile(
            r'^(?P<ip>\S+)\s+\S+\s+(?P<user>\S+)\s+'
            r'\[(?P<timestamp>[^\]]+)\]\s+'
            r'"(?P<method>\S+)\s+(?P<path>\S+)\s+(?P<protocol>\S+)"\s+'
            r'(?P<status>\d{3})\s+(?P<size>\d+|-)'
            r'(?:\s+"(?P<referer>[^"]*)")?\s*(?:"(?P<user_agent>[^"]*)")?'
            r'(?:\s+(?P<request_time>[\d.]+))?'
        )
        match = pattern.match(line)
        if not match:
            return None

        groups = match.groupdict()
        status = int(groups["status"])

        if status >= 500:
            severity = Severity.ERROR
        elif status >= 400:
            severity = Severity.WARNING
        else:
            severity = Severity.INFO

        return {
            "raw": line,
            "format": fmt,
            "fields": {
                "timestamp": groups["timestamp"],
                "ip": groups["ip"],
                "method": groups["method"],
                "path": groups["path"],
                "status": status,
                "size": int(groups["size"]) if groups["size"] != "-" else 0,
                "message": f"{groups['method']} {groups['path']} {status}",
            },
            "metadata": {
                "user": groups.get("user", "-"),
                "referer": groups.get("referer", ""),
                "user_agent": groups.get("user_agent", ""),
                "request_time": groups.get("request_time"),
                "protocol": groups.get("protocol", ""),
            },
            "severity": severity.value,
        }

    def _parse_app_line(
        self, line: str, fmt: str
    ) -> Optional[Dict[str, Any]]:
        """Parse an application log line."""
        pattern = re.compile(
            r"^(?P<timestamp>\d{4}-\d{2}-\d{2}[\sT]\d{2}:\d{2}:\d{2}(?:[.,]\d{3})?)\s+"
            r"(?:\[(?P<thread>[^\]]+)\]\s+)?"
            r"(?P<level>\w+)\s+"
            r"(?:(?P<logger>\S+)\s*[-:]\s*)?"
            r"(?P<message>.+)$"
        )
        match = pattern.match(line)
        if not match:
            return None

        groups = match.groupdict()
        severity = self._detect_severity(groups.get("level", "INFO"))

        return {
            "raw": line,
            "format": "app_log",
            "fields": {
                "timestamp": groups["timestamp"],
                "level": groups.get("level", "INFO"),
                "message": groups["message"],
            },
            "metadata": {
                "thread": groups.get("thread"),
                "logger": groups.get("logger"),
            },
            "severity": severity.value,
        }

    def _parse_unstructured(self, line: str) -> Dict[str, Any]:
        """Parse an unstructured log line, extracting what we can."""
        severity = self._detect_severity(line)

        # Try to extract a timestamp
        timestamp_match = re.search(
            r"\d{4}-\d{2}-\d{2}[\sT]\d{2}:\d{2}:\d{2}", line
        )
        timestamp = timestamp_match.group(0) if timestamp_match else None

        return {
            "raw": line,
            "format": "unstructured",
            "fields": {
                "message": line,
                "timestamp": timestamp,
            },
            "metadata": {},
            "severity": severity.value,
        }

    @staticmethod
    def _detect_severity(text: str) -> Severity:
        """Detect severity level from text content."""
        for pattern, severity in SEVERITY_PATTERNS:
            if pattern.search(text):
                return severity
        return Severity.INFO
