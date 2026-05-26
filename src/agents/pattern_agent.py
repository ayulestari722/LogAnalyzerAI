"""
PatternAgent — Regex pattern matching and frequency analysis.

Identifies recurring patterns, extracts structured fields, and performs
frequency analysis on log message templates.
"""

import re
from collections import defaultdict, Counter
from typing import Any, Dict, List, Optional, Tuple

from src.agents.base import BaseAgent
from src.models.analysis_state import AnalysisState
from src.models.log_entry import LogEntry, Severity


# Common patterns to detect in log messages
KNOWN_PATTERNS = {
    "ip_address": re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"),
    "email": re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b"),
    "uuid": re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"),
    "url": re.compile(r"https?://[^\s\"'<>]+"),
    "file_path": re.compile(r"(?:/[\w.-]+)+(?:\.\w+)?"),
    "stack_trace": re.compile(r"(?:at\s+[\w.$]+\([\w.]+:\d+\))|(?:File\s+\"[^\"]+\",\s+line\s+\d+)"),
    "exception": re.compile(r"\b(?:\w+(?:Error|Exception|Fault|Failure))\b"),
    "http_method": re.compile(r"\b(?:GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\b"),
    "status_code": re.compile(r"\b[1-5]\d{2}\b"),
    "duration": re.compile(r"\b\d+(?:\.\d+)?\s*(?:ms|s|sec|seconds|milliseconds)\b"),
    "memory": re.compile(r"\b\d+(?:\.\d+)?\s*(?:MB|GB|KB|bytes|B)\b"),
    "port": re.compile(r":(\d{2,5})\b"),
    "timestamp_inline": re.compile(r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}"),
    "hex_value": re.compile(r"\b0x[0-9a-fA-F]+\b"),
    "json_fragment": re.compile(r"\{[^{}]*\}"),
}

# Error-related patterns
ERROR_PATTERNS = {
    "connection_refused": re.compile(r"(?i)connection\s+refused"),
    "timeout": re.compile(r"(?i)(?:timed?\s*out|timeout)"),
    "permission_denied": re.compile(r"(?i)permission\s+denied|access\s+denied|forbidden"),
    "not_found": re.compile(r"(?i)not\s+found|no\s+such\s+file|404"),
    "out_of_memory": re.compile(r"(?i)out\s+of\s+memory|OOM|heap\s+space"),
    "disk_full": re.compile(r"(?i)no\s+space\s+left|disk\s+full"),
    "authentication_failure": re.compile(r"(?i)auth(?:entication)?\s+fail|invalid\s+(?:credentials|token|password)"),
    "rate_limit": re.compile(r"(?i)rate\s+limit|too\s+many\s+requests|429"),
    "ssl_error": re.compile(r"(?i)ssl|tls|certificate\s+(?:expired|invalid|error)"),
    "database_error": re.compile(r"(?i)(?:database|db|sql)\s+(?:error|failure|connection)|deadlock"),
}


class PatternAgent(BaseAgent):
    """Agent that performs regex pattern matching and frequency analysis.

    Identifies recurring message templates, extracts structured fields,
    and categorizes log entries by detected patterns.
    """

    def __init__(self, config: Optional[Dict[str, Any]] = None) -> None:
        super().__init__(name="pattern", config=config)
        self._min_pattern_frequency: int = self.config.get("min_pattern_frequency", 2)
        self._max_patterns_reported: int = self.config.get("max_patterns_reported", 50)
        self._template_cache: Dict[str, str] = {}

    async def analyze(self, state: AnalysisState) -> Dict[str, Any]:
        """Perform pattern matching and frequency analysis on log entries.

        Args:
            state: Analysis state with parsed log entries.

        Returns:
            Dictionary with pattern frequencies, extracted fields, and categorization.
        """
        entries = state.log_entries
        if not entries:
            return {
                "patterns_found": {},
                "error_patterns": {},
                "message_templates": [],
                "extracted_fields": {},
                "total_patterns": 0,
            }

        # Detect known patterns across all entries
        pattern_matches = self._detect_known_patterns(entries)

        # Detect error-specific patterns
        error_pattern_matches = self._detect_error_patterns(entries)

        # Generate message templates via normalization
        templates = self._generate_message_templates(entries)

        # Extract structured fields from patterns
        extracted_fields = self._extract_fields(entries)

        # Frequency analysis of templates
        template_frequency = self._analyze_template_frequency(templates)

        # Build pattern co-occurrence matrix
        co_occurrences = self._analyze_co_occurrences(entries)

        state.agent_results["pattern"] = {
            "pattern_matches": pattern_matches,
            "error_patterns": error_pattern_matches,
            "templates": template_frequency,
        }

        return {
            "patterns_found": pattern_matches,
            "error_patterns": error_pattern_matches,
            "message_templates": template_frequency[:self._max_patterns_reported],
            "extracted_fields": extracted_fields,
            "co_occurrences": co_occurrences[:20],
            "total_patterns": sum(len(v) for v in pattern_matches.values()),
            "unique_templates": len(template_frequency),
        }

    def _detect_known_patterns(
        self, entries: List[LogEntry]
    ) -> Dict[str, List[Dict[str, Any]]]:
        """Detect known patterns (IPs, URLs, exceptions, etc.) in log messages."""
        results: Dict[str, List[Dict[str, Any]]] = defaultdict(list)

        for entry in entries:
            message = entry.message
            for pattern_name, pattern_re in KNOWN_PATTERNS.items():
                matches = pattern_re.findall(message)
                if matches:
                    for match_val in matches:
                        match_str = match_val if isinstance(match_val, str) else str(match_val)
                        results[pattern_name].append({
                            "value": match_str,
                            "line_number": entry.line_number,
                            "source": entry.source,
                        })

        # Deduplicate and count
        summary: Dict[str, List[Dict[str, Any]]] = {}
        for pattern_name, match_list in results.items():
            value_counts: Counter = Counter(m["value"] for m in match_list)
            top_values = value_counts.most_common(10)
            summary[pattern_name] = [
                {"value": val, "count": count}
                for val, count in top_values
            ]

        return summary

    def _detect_error_patterns(
        self, entries: List[LogEntry]
    ) -> Dict[str, List[Dict[str, Any]]]:
        """Detect error-specific patterns in log messages."""
        results: Dict[str, List[Dict[str, Any]]] = defaultdict(list)

        for entry in entries:
            message = entry.message
            for pattern_name, pattern_re in ERROR_PATTERNS.items():
                if pattern_re.search(message):
                    results[pattern_name].append({
                        "line_number": entry.line_number,
                        "message": message[:200],
                        "severity": entry.severity.value,
                        "timestamp": str(entry.timestamp) if entry.timestamp else None,
                    })

        return dict(results)

    def _generate_message_templates(
        self, entries: List[LogEntry]
    ) -> List[str]:
        """Generate normalized message templates by replacing variable parts."""
        templates: List[str] = []

        for entry in entries:
            template = self._normalize_to_template(entry.message)
            templates.append(template)

        return templates

    def _normalize_to_template(self, message: str) -> str:
        """Normalize a message into a template by replacing variable parts."""
        if message in self._template_cache:
            return self._template_cache[message]

        template = message
        # Replace UUIDs
        template = re.sub(
            r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
            "{UUID}", template
        )
        # Replace IP addresses
        template = re.sub(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", "{IP}", template)
        # Replace hex values
        template = re.sub(r"\b0x[0-9a-fA-F]+\b", "{HEX}", template)
        # Replace quoted strings
        template = re.sub(r'"[^"]*"', '"{STR}"', template)
        template = re.sub(r"'[^']*'", "'{STR}'", template)
        # Replace numbers
        template = re.sub(r"\b\d+(?:\.\d+)?\b", "{NUM}", template)
        # Replace file paths
        template = re.sub(r"(?:/[\w.-]+){2,}", "{PATH}", template)

        # Cache for performance
        if len(self._template_cache) < 10000:
            self._template_cache[message] = template

        return template

    def _analyze_template_frequency(
        self, templates: List[str]
    ) -> List[Dict[str, Any]]:
        """Analyze frequency of message templates."""
        counter = Counter(templates)
        total = len(templates)

        frequency_list: List[Dict[str, Any]] = []
        for template, count in counter.most_common(self._max_patterns_reported):
            if count >= self._min_pattern_frequency:
                frequency_list.append({
                    "template": template[:200],
                    "count": count,
                    "percentage": round(count / total * 100, 2) if total > 0 else 0,
                })

        return frequency_list

    def _extract_fields(
        self, entries: List[LogEntry]
    ) -> Dict[str, Dict[str, int]]:
        """Extract and aggregate structured fields from log entries."""
        field_values: Dict[str, Counter] = defaultdict(Counter)

        for entry in entries:
            # Extract IPs
            ips = KNOWN_PATTERNS["ip_address"].findall(entry.message)
            for ip in ips:
                field_values["ip_addresses"][ip] += 1

            # Extract URLs
            urls = KNOWN_PATTERNS["url"].findall(entry.message)
            for url in urls:
                field_values["urls"][url[:100]] += 1

            # Extract exceptions
            exceptions = KNOWN_PATTERNS["exception"].findall(entry.message)
            for exc in exceptions:
                field_values["exceptions"][exc] += 1

            # Extract HTTP methods
            methods = KNOWN_PATTERNS["http_method"].findall(entry.message)
            for method in methods:
                field_values["http_methods"][method] += 1

            # Extract durations
            durations = KNOWN_PATTERNS["duration"].findall(entry.message)
            for dur in durations:
                field_values["durations"][dur] += 1

        # Convert to top-N summaries
        result: Dict[str, Dict[str, int]] = {}
        for field_name, counter in field_values.items():
            result[field_name] = dict(counter.most_common(20))

        return result

    def _analyze_co_occurrences(
        self, entries: List[LogEntry]
    ) -> List[Dict[str, Any]]:
        """Analyze which patterns tend to co-occur in the same log entries."""
        co_occurrence_counter: Counter = Counter()

        for entry in entries:
            message = entry.message
            found_patterns: List[str] = []

            for pattern_name, pattern_re in KNOWN_PATTERNS.items():
                if pattern_re.search(message):
                    found_patterns.append(pattern_name)

            # Generate pairs
            for i in range(len(found_patterns)):
                for j in range(i + 1, len(found_patterns)):
                    pair = tuple(sorted([found_patterns[i], found_patterns[j]]))
                    co_occurrence_counter[pair] += 1

        results: List[Dict[str, Any]] = []
        for pair, count in co_occurrence_counter.most_common(20):
            if count >= self._min_pattern_frequency:
                results.append({
                    "pattern_a": pair[0],
                    "pattern_b": pair[1],
                    "co_occurrence_count": count,
                })

        return results
