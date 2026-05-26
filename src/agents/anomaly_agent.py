"""
AnomalyAgent — Detects spikes, gaps, and unusual patterns via statistical methods.

Uses z-score analysis, moving averages, and gap detection to identify
anomalous behavior in log streams.
"""

import math
from collections import defaultdict
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Tuple

from src.agents.base import BaseAgent
from src.models.analysis_state import AnalysisState
from src.models.log_entry import LogEntry, Severity


class AnomalyAgent(BaseAgent):
    """Agent that detects statistical anomalies in log data.

    Implements multiple detection strategies:
    - Rate spike detection (z-score based)
    - Time gap detection (missing expected log entries)
    - Error burst detection (sudden increase in error severity)
    - Volume anomaly detection (unusual log volume per time window)
    """

    def __init__(self, config: Optional[Dict[str, Any]] = None) -> None:
        super().__init__(name="anomaly", config=config)
        self._z_score_threshold: float = self.config.get("z_score_threshold", 2.5)
        self._gap_threshold_seconds: float = self.config.get("gap_threshold_seconds", 300.0)
        self._window_size_seconds: int = self.config.get("window_size_seconds", 60)
        self._min_data_points: int = self.config.get("min_data_points", 5)
        self._error_burst_threshold: int = self.config.get("error_burst_threshold", 5)

    async def analyze(self, state: AnalysisState) -> Dict[str, Any]:
        """Detect anomalies in the parsed log entries.

        Args:
            state: Analysis state with parsed log entries.

        Returns:
            Dictionary containing detected anomalies categorized by type.
        """
        entries = state.log_entries
        if not entries:
            return {
                "anomalies": [],
                "total_anomalies": 0,
                "anomaly_types": {},
                "severity_distribution": {},
            }

        anomalies: List[Dict[str, Any]] = []

        # Run all detection strategies
        rate_anomalies = self._detect_rate_spikes(entries)
        anomalies.extend(rate_anomalies)

        gap_anomalies = self._detect_time_gaps(entries)
        anomalies.extend(gap_anomalies)

        error_bursts = self._detect_error_bursts(entries)
        anomalies.extend(error_bursts)

        volume_anomalies = self._detect_volume_anomalies(entries)
        anomalies.extend(volume_anomalies)

        pattern_anomalies = self._detect_new_patterns(entries)
        anomalies.extend(pattern_anomalies)

        # Categorize results
        anomaly_types: Dict[str, int] = defaultdict(int)
        severity_dist: Dict[str, int] = defaultdict(int)
        for anomaly in anomalies:
            anomaly_types[anomaly["type"]] += 1
            severity_dist[anomaly["severity"]] += 1

        # Sort by severity score descending
        severity_order = {"critical": 4, "high": 3, "medium": 2, "low": 1}
        anomalies.sort(
            key=lambda a: severity_order.get(a["severity"], 0), reverse=True
        )

        state.agent_results["anomaly"] = {
            "anomalies": anomalies,
            "total_anomalies": len(anomalies),
        }

        return {
            "anomalies": anomalies[:50],  # Top 50 most severe
            "total_anomalies": len(anomalies),
            "anomaly_types": dict(anomaly_types),
            "severity_distribution": dict(severity_dist),
        }

    def _detect_rate_spikes(self, entries: List[LogEntry]) -> List[Dict[str, Any]]:
        """Detect sudden spikes in log rate using z-score analysis."""
        timestamped = [e for e in entries if e.timestamp is not None]
        if len(timestamped) < self._min_data_points:
            return []

        timestamped.sort(key=lambda e: e.timestamp)  # type: ignore

        # Bucket entries into time windows
        window_counts = self._bucket_by_window(timestamped)
        if len(window_counts) < 3:
            return []

        counts = list(window_counts.values())
        mean = sum(counts) / len(counts)
        variance = sum((c - mean) ** 2 for c in counts) / len(counts)
        std_dev = math.sqrt(variance) if variance > 0 else 1.0

        anomalies: List[Dict[str, Any]] = []
        windows = list(window_counts.keys())

        for i, (window_key, count) in enumerate(zip(windows, counts)):
            z_score = (count - mean) / std_dev if std_dev > 0 else 0.0
            if abs(z_score) >= self._z_score_threshold:
                severity = "critical" if abs(z_score) > 4.0 else "high" if abs(z_score) > 3.0 else "medium"
                anomalies.append({
                    "type": "rate_spike",
                    "severity": severity,
                    "timestamp": window_key,
                    "description": f"Log rate spike detected: {count} entries in window "
                                   f"(mean={mean:.1f}, z-score={z_score:.2f})",
                    "z_score": round(z_score, 3),
                    "count": count,
                    "mean": round(mean, 2),
                    "std_dev": round(std_dev, 2),
                })

        return anomalies

    def _detect_time_gaps(self, entries: List[LogEntry]) -> List[Dict[str, Any]]:
        """Detect unexpected gaps in log timestamps."""
        timestamped = [e for e in entries if e.timestamp is not None]
        if len(timestamped) < 2:
            return []

        timestamped.sort(key=lambda e: e.timestamp)  # type: ignore

        # Calculate inter-arrival times
        deltas: List[float] = []
        for i in range(1, len(timestamped)):
            t1 = timestamped[i - 1].timestamp
            t2 = timestamped[i].timestamp
            if t1 and t2:
                delta = (t2 - t1).total_seconds()
                deltas.append(delta)

        if not deltas:
            return []

        # Use median-based detection for gaps
        sorted_deltas = sorted(deltas)
        median_delta = sorted_deltas[len(sorted_deltas) // 2]
        threshold = max(self._gap_threshold_seconds, median_delta * 10)

        anomalies: List[Dict[str, Any]] = []
        for i, delta in enumerate(deltas):
            if delta >= threshold:
                before_entry = timestamped[i]
                after_entry = timestamped[i + 1]
                severity = "high" if delta > threshold * 3 else "medium"
                anomalies.append({
                    "type": "time_gap",
                    "severity": severity,
                    "timestamp": str(before_entry.timestamp),
                    "description": f"Gap of {delta:.1f}s detected between entries "
                                   f"(threshold={threshold:.1f}s, median={median_delta:.1f}s)",
                    "gap_seconds": round(delta, 2),
                    "threshold_seconds": round(threshold, 2),
                    "before_line": before_entry.line_number,
                    "after_line": after_entry.line_number,
                })

        return anomalies

    def _detect_error_bursts(self, entries: List[LogEntry]) -> List[Dict[str, Any]]:
        """Detect bursts of error-level log entries."""
        timestamped = [e for e in entries if e.timestamp is not None]
        if not timestamped:
            return []

        timestamped.sort(key=lambda e: e.timestamp)  # type: ignore

        # Sliding window for error counting
        error_severities = {Severity.ERROR, Severity.CRITICAL}
        window_errors: List[Tuple[Optional[datetime], int]] = []

        window_start = 0
        for i, entry in enumerate(timestamped):
            # Move window start forward
            while window_start < i:
                t_start = timestamped[window_start].timestamp
                t_current = entry.timestamp
                if t_start and t_current:
                    if (t_current - t_start).total_seconds() > self._window_size_seconds:
                        window_start += 1
                    else:
                        break
                else:
                    break

            # Count errors in current window
            error_count = sum(
                1 for e in timestamped[window_start:i + 1]
                if e.severity in error_severities
            )

            if error_count >= self._error_burst_threshold:
                window_errors.append((entry.timestamp, error_count))

        # Deduplicate overlapping detections
        anomalies: List[Dict[str, Any]] = []
        last_reported: Optional[datetime] = None

        for ts, count in window_errors:
            if last_reported and ts:
                if (ts - last_reported).total_seconds() < self._window_size_seconds:
                    continue

            severity = "critical" if count >= self._error_burst_threshold * 2 else "high"
            anomalies.append({
                "type": "error_burst",
                "severity": severity,
                "timestamp": str(ts),
                "description": f"Error burst: {count} errors within "
                               f"{self._window_size_seconds}s window",
                "error_count": count,
                "window_seconds": self._window_size_seconds,
            })
            last_reported = ts

        return anomalies

    def _detect_volume_anomalies(self, entries: List[LogEntry]) -> List[Dict[str, Any]]:
        """Detect unusual log volume patterns per source."""
        source_counts: Dict[str, int] = defaultdict(int)
        for entry in entries:
            source_counts[entry.source] += 1

        if len(source_counts) < 2:
            return []

        counts = list(source_counts.values())
        mean = sum(counts) / len(counts)
        variance = sum((c - mean) ** 2 for c in counts) / len(counts)
        std_dev = math.sqrt(variance) if variance > 0 else 1.0

        anomalies: List[Dict[str, Any]] = []
        for source, count in source_counts.items():
            z_score = (count - mean) / std_dev if std_dev > 0 else 0.0
            if abs(z_score) >= self._z_score_threshold:
                anomalies.append({
                    "type": "volume_anomaly",
                    "severity": "medium",
                    "timestamp": None,
                    "description": f"Source '{source}' has unusual volume: "
                                   f"{count} entries (mean={mean:.1f}, z={z_score:.2f})",
                    "source": source,
                    "count": count,
                    "z_score": round(z_score, 3),
                })

        return anomalies

    def _detect_new_patterns(self, entries: List[LogEntry]) -> List[Dict[str, Any]]:
        """Detect messages that don't match common patterns (novelty detection)."""
        if len(entries) < 10:
            return []

        # Build frequency map of message prefixes (first 50 chars)
        prefix_counts: Dict[str, int] = defaultdict(int)
        for entry in entries:
            prefix = entry.message[:50] if entry.message else ""
            # Normalize numbers to detect pattern variations
            normalized = self._normalize_message(prefix)
            prefix_counts[normalized] += 1

        # Find entries with very rare patterns (appear only once)
        total = len(entries)
        threshold = max(1, total * 0.01)  # Less than 1% occurrence

        anomalies: List[Dict[str, Any]] = []
        seen_patterns: set = set()

        for entry in entries:
            prefix = entry.message[:50] if entry.message else ""
            normalized = self._normalize_message(prefix)

            if prefix_counts[normalized] <= threshold and normalized not in seen_patterns:
                seen_patterns.add(normalized)
                if entry.severity in (Severity.ERROR, Severity.CRITICAL):
                    anomalies.append({
                        "type": "novel_pattern",
                        "severity": "low",
                        "timestamp": str(entry.timestamp) if entry.timestamp else None,
                        "description": f"Rare log pattern detected: '{entry.message[:80]}'",
                        "line_number": entry.line_number,
                        "occurrences": prefix_counts[normalized],
                    })

        return anomalies[:10]  # Limit novel pattern reports

    def _bucket_by_window(
        self, entries: List[LogEntry]
    ) -> Dict[str, int]:
        """Bucket timestamped entries into fixed-size time windows."""
        buckets: Dict[str, int] = {}

        for entry in entries:
            if entry.timestamp is None:
                continue
            # Round down to window boundary
            ts = entry.timestamp
            window_start = ts.replace(
                second=(ts.second // self._window_size_seconds) * self._window_size_seconds
                if self._window_size_seconds <= 60 else 0,
                microsecond=0,
            )
            key = window_start.isoformat()
            buckets[key] = buckets.get(key, 0) + 1

        return buckets

    @staticmethod
    def _normalize_message(message: str) -> str:
        """Normalize a message by replacing numbers and UUIDs with placeholders."""
        import re
        # Replace UUIDs
        result = re.sub(
            r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
            "<UUID>",
            message,
        )
        # Replace hex strings
        result = re.sub(r"0x[0-9a-fA-F]+", "<HEX>", result)
        # Replace numbers
        result = re.sub(r"\b\d+\b", "<N>", result)
        return result
