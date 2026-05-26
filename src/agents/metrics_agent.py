"""
MetricsAgent — Aggregate statistics: error rate, latency percentiles, throughput.

Computes comprehensive metrics from parsed log entries including
rate calculations, percentile distributions, and trend analysis.
"""

import math
import re
from collections import defaultdict, Counter
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Tuple

from src.agents.base import BaseAgent
from src.models.analysis_state import AnalysisState
from src.models.log_entry import LogEntry, Severity


class MetricsAgent(BaseAgent):
    """Agent that computes aggregate statistics from log data.

    Calculates:
    - Error rates (total, per-source, per-window)
    - Latency percentiles (p50, p90, p95, p99)
    - Throughput (requests/second, logs/minute)
    - Status code distributions
    - Source-level breakdowns
    - Trend analysis over time windows
    """

    def __init__(self, config: Optional[Dict[str, Any]] = None) -> None:
        super().__init__(name="metrics", config=config)
        self._percentiles: List[float] = self.config.get(
            "percentiles", [0.50, 0.75, 0.90, 0.95, 0.99]
        )
        self._window_size_seconds: int = self.config.get("window_size_seconds", 60)
        self._trend_windows: int = self.config.get("trend_windows", 10)

    async def analyze(self, state: AnalysisState) -> Dict[str, Any]:
        """Compute aggregate metrics from log entries.

        Args:
            state: Analysis state with parsed log entries.

        Returns:
            Dictionary with comprehensive metrics and statistics.
        """
        entries = state.log_entries
        if not entries:
            return self._empty_metrics()

        # Core metrics
        severity_metrics = self._compute_severity_metrics(entries)
        throughput_metrics = self._compute_throughput(entries)
        latency_metrics = self._compute_latency_percentiles(entries)
        status_metrics = self._compute_status_distribution(entries)
        source_metrics = self._compute_source_metrics(entries)
        trend_metrics = self._compute_trends(entries)
        size_metrics = self._compute_size_metrics(entries)
        top_paths = self._compute_top_paths(entries)
        error_details = self._compute_error_breakdown(entries)

        result = {
            "total_entries": len(entries),
            "severity": severity_metrics,
            "throughput": throughput_metrics,
            "latency": latency_metrics,
            "status_codes": status_metrics,
            "by_source": source_metrics,
            "trends": trend_metrics,
            "response_sizes": size_metrics,
            "top_paths": top_paths,
            "error_breakdown": error_details,
            "time_range": self._compute_time_range(entries),
        }

        state.agent_results["metrics"] = result
        return result

    def _empty_metrics(self) -> Dict[str, Any]:
        """Return empty metrics structure."""
        return {
            "total_entries": 0,
            "severity": {},
            "throughput": {},
            "latency": {},
            "status_codes": {},
            "by_source": {},
            "trends": [],
            "response_sizes": {},
            "top_paths": [],
            "error_breakdown": {},
            "time_range": None,
        }

    def _compute_severity_metrics(
        self, entries: List[LogEntry]
    ) -> Dict[str, Any]:
        """Compute severity distribution and error rates."""
        total = len(entries)
        severity_counts: Dict[str, int] = defaultdict(int)

        for entry in entries:
            severity_counts[entry.severity.value] += 1

        error_count = severity_counts.get("error", 0) + severity_counts.get("critical", 0)
        warning_count = severity_counts.get("warning", 0)

        return {
            "distribution": dict(severity_counts),
            "error_count": error_count,
            "warning_count": warning_count,
            "error_rate_percent": round((error_count / total) * 100, 3) if total > 0 else 0,
            "warning_rate_percent": round((warning_count / total) * 100, 3) if total > 0 else 0,
            "healthy_rate_percent": round(
                ((total - error_count - warning_count) / total) * 100, 3
            ) if total > 0 else 0,
        }

    def _compute_throughput(self, entries: List[LogEntry]) -> Dict[str, Any]:
        """Compute throughput metrics (entries per time unit)."""
        timestamped = [e for e in entries if e.timestamp is not None]
        if len(timestamped) < 2:
            return {
                "entries_per_second": 0,
                "entries_per_minute": 0,
                "peak_per_second": 0,
                "peak_per_minute": 0,
            }

        timestamped.sort(key=lambda e: e.timestamp)  # type: ignore
        first_ts = timestamped[0].timestamp
        last_ts = timestamped[-1].timestamp
        duration_seconds = (last_ts - first_ts).total_seconds()  # type: ignore

        if duration_seconds <= 0:
            return {
                "entries_per_second": float(len(timestamped)),
                "entries_per_minute": float(len(timestamped)),
                "peak_per_second": float(len(timestamped)),
                "peak_per_minute": float(len(timestamped)),
            }

        avg_per_second = len(timestamped) / duration_seconds
        avg_per_minute = avg_per_second * 60

        # Calculate peak rates
        second_buckets: Dict[str, int] = defaultdict(int)
        minute_buckets: Dict[str, int] = defaultdict(int)

        for entry in timestamped:
            ts = entry.timestamp
            sec_key = ts.strftime("%Y-%m-%d %H:%M:%S")  # type: ignore
            min_key = ts.strftime("%Y-%m-%d %H:%M")  # type: ignore
            second_buckets[sec_key] += 1
            minute_buckets[min_key] += 1

        peak_per_second = max(second_buckets.values()) if second_buckets else 0
        peak_per_minute = max(minute_buckets.values()) if minute_buckets else 0

        return {
            "entries_per_second": round(avg_per_second, 3),
            "entries_per_minute": round(avg_per_minute, 3),
            "peak_per_second": peak_per_second,
            "peak_per_minute": peak_per_minute,
            "duration_seconds": round(duration_seconds, 2),
            "total_timestamped": len(timestamped),
        }

    def _compute_latency_percentiles(
        self, entries: List[LogEntry]
    ) -> Dict[str, Any]:
        """Compute latency percentile distribution."""
        latencies: List[float] = []

        for entry in entries:
            # Extract from metadata
            if "request_time" in entry.metadata:
                try:
                    val = float(entry.metadata["request_time"])
                    latencies.append(val * 1000)  # Convert to ms
                except (ValueError, TypeError):
                    pass
            elif "duration_ms" in entry.metadata:
                try:
                    latencies.append(float(entry.metadata["duration_ms"]))
                except (ValueError, TypeError):
                    pass

            # Extract from message
            ms_match = re.search(r"(\d+(?:\.\d+)?)\s*ms\b", entry.message)
            if ms_match:
                latencies.append(float(ms_match.group(1)))

        if not latencies:
            return {"available": False, "sample_count": 0}

        sorted_lat = sorted(latencies)
        n = len(sorted_lat)

        percentile_results: Dict[str, float] = {}
        for p in self._percentiles:
            idx = int(n * p)
            idx = min(idx, n - 1)
            key = f"p{int(p * 100)}"
            percentile_results[key] = round(sorted_lat[idx], 3)

        return {
            "available": True,
            "sample_count": n,
            "min_ms": round(sorted_lat[0], 3),
            "max_ms": round(sorted_lat[-1], 3),
            "mean_ms": round(sum(sorted_lat) / n, 3),
            "median_ms": round(sorted_lat[n // 2], 3),
            "std_dev_ms": round(self._std_dev(sorted_lat), 3),
            "percentiles": percentile_results,
        }

    def _compute_status_distribution(
        self, entries: List[LogEntry]
    ) -> Dict[str, Any]:
        """Compute HTTP status code distribution."""
        status_counts: Dict[int, int] = defaultdict(int)
        status_class_counts: Dict[str, int] = defaultdict(int)

        for entry in entries:
            status = entry.metadata.get("status")
            if status is not None:
                try:
                    code = int(status)
                    status_counts[code] += 1
                    class_key = f"{code // 100}xx"
                    status_class_counts[class_key] += 1
                except (ValueError, TypeError):
                    pass

        total_with_status = sum(status_counts.values())
        success_rate = 0.0
        if total_with_status > 0:
            success = status_class_counts.get("2xx", 0) + status_class_counts.get("3xx", 0)
            success_rate = round((success / total_with_status) * 100, 2)

        return {
            "by_code": dict(sorted(status_counts.items())),
            "by_class": dict(sorted(status_class_counts.items())),
            "total_with_status": total_with_status,
            "success_rate_percent": success_rate,
            "error_rate_percent": round(100 - success_rate, 2) if total_with_status > 0 else 0,
        }

    def _compute_source_metrics(
        self, entries: List[LogEntry]
    ) -> Dict[str, Dict[str, Any]]:
        """Compute per-source metrics breakdown."""
        by_source: Dict[str, List[LogEntry]] = defaultdict(list)
        for entry in entries:
            by_source[entry.source].append(entry)

        result: Dict[str, Dict[str, Any]] = {}
        for source, source_entries in by_source.items():
            total = len(source_entries)
            errors = sum(
                1 for e in source_entries
                if e.severity in (Severity.ERROR, Severity.CRITICAL)
            )
            warnings = sum(
                1 for e in source_entries if e.severity == Severity.WARNING
            )

            result[source] = {
                "total_entries": total,
                "error_count": errors,
                "warning_count": warnings,
                "error_rate_percent": round((errors / total) * 100, 2) if total > 0 else 0,
                "severity_distribution": dict(
                    Counter(e.severity.value for e in source_entries)
                ),
            }

        return result

    def _compute_trends(self, entries: List[LogEntry]) -> List[Dict[str, Any]]:
        """Compute metrics trends over time windows."""
        timestamped = [e for e in entries if e.timestamp is not None]
        if len(timestamped) < 2:
            return []

        timestamped.sort(key=lambda e: e.timestamp)  # type: ignore
        first_ts = timestamped[0].timestamp
        last_ts = timestamped[-1].timestamp
        total_duration = (last_ts - first_ts).total_seconds()  # type: ignore

        if total_duration <= 0:
            return []

        # Determine window size
        window_duration = max(
            self._window_size_seconds,
            total_duration / self._trend_windows,
        )

        windows: List[Dict[str, Any]] = []
        window_start = first_ts
        window_delta = timedelta(seconds=window_duration)

        while window_start < last_ts:  # type: ignore
            window_end = window_start + window_delta  # type: ignore
            window_entries = [
                e for e in timestamped
                if window_start <= e.timestamp < window_end  # type: ignore
            ]

            if window_entries:
                error_count = sum(
                    1 for e in window_entries
                    if e.severity in (Severity.ERROR, Severity.CRITICAL)
                )
                windows.append({
                    "window_start": window_start.isoformat(),  # type: ignore
                    "window_end": window_end.isoformat(),  # type: ignore
                    "entry_count": len(window_entries),
                    "error_count": error_count,
                    "error_rate_percent": round(
                        (error_count / len(window_entries)) * 100, 2
                    ),
                    "entries_per_second": round(
                        len(window_entries) / window_duration, 3
                    ),
                })

            window_start = window_end  # type: ignore

        # Calculate trend direction
        if len(windows) >= 2:
            first_half = windows[:len(windows) // 2]
            second_half = windows[len(windows) // 2:]

            first_avg_rate = (
                sum(w["error_rate_percent"] for w in first_half) / len(first_half)
                if first_half else 0
            )
            second_avg_rate = (
                sum(w["error_rate_percent"] for w in second_half) / len(second_half)
                if second_half else 0
            )

            for window in windows:
                window["trend_direction"] = (
                    "increasing" if second_avg_rate > first_avg_rate * 1.1
                    else "decreasing" if second_avg_rate < first_avg_rate * 0.9
                    else "stable"
                )

        return windows

    def _compute_size_metrics(self, entries: List[LogEntry]) -> Dict[str, Any]:
        """Compute response size metrics from access logs."""
        sizes: List[int] = []

        for entry in entries:
            size = entry.metadata.get("size")
            if size is not None:
                try:
                    s = int(size)
                    if s > 0:
                        sizes.append(s)
                except (ValueError, TypeError):
                    pass

        if not sizes:
            return {"available": False, "sample_count": 0}

        sorted_sizes = sorted(sizes)
        n = len(sorted_sizes)

        return {
            "available": True,
            "sample_count": n,
            "total_bytes": sum(sorted_sizes),
            "min_bytes": sorted_sizes[0],
            "max_bytes": sorted_sizes[-1],
            "mean_bytes": round(sum(sorted_sizes) / n, 2),
            "median_bytes": sorted_sizes[n // 2],
            "p95_bytes": sorted_sizes[int(n * 0.95)] if n > 1 else sorted_sizes[0],
        }

    def _compute_top_paths(
        self, entries: List[LogEntry]
    ) -> List[Dict[str, Any]]:
        """Compute most frequently accessed paths."""
        path_stats: Dict[str, Dict[str, Any]] = defaultdict(
            lambda: {"count": 0, "errors": 0, "total_size": 0, "latencies": []}
        )

        for entry in entries:
            path = entry.metadata.get("path")
            if path:
                path_stats[path]["count"] += 1
                status = entry.metadata.get("status", 200)
                try:
                    if int(status) >= 400:
                        path_stats[path]["errors"] += 1
                except (ValueError, TypeError):
                    pass

                size = entry.metadata.get("size", 0)
                try:
                    path_stats[path]["total_size"] += int(size)
                except (ValueError, TypeError):
                    pass

                req_time = entry.metadata.get("request_time")
                if req_time:
                    try:
                        path_stats[path]["latencies"].append(float(req_time) * 1000)
                    except (ValueError, TypeError):
                        pass

        # Build top paths list
        top_paths: List[Dict[str, Any]] = []
        for path, stats in sorted(
            path_stats.items(), key=lambda x: x[1]["count"], reverse=True
        )[:20]:
            path_info: Dict[str, Any] = {
                "path": path,
                "count": stats["count"],
                "error_count": stats["errors"],
                "error_rate_percent": round(
                    (stats["errors"] / stats["count"]) * 100, 2
                ) if stats["count"] > 0 else 0,
                "total_size_bytes": stats["total_size"],
            }
            if stats["latencies"]:
                sorted_lat = sorted(stats["latencies"])
                path_info["avg_latency_ms"] = round(
                    sum(sorted_lat) / len(sorted_lat), 2
                )
                path_info["p95_latency_ms"] = round(
                    sorted_lat[int(len(sorted_lat) * 0.95)], 2
                ) if len(sorted_lat) > 1 else round(sorted_lat[0], 2)

            top_paths.append(path_info)

        return top_paths

    def _compute_error_breakdown(
        self, entries: List[LogEntry]
    ) -> Dict[str, Any]:
        """Compute detailed error breakdown."""
        error_entries = [
            e for e in entries
            if e.severity in (Severity.ERROR, Severity.CRITICAL)
        ]

        if not error_entries:
            return {"total_errors": 0, "categories": {}}

        # Categorize errors
        categories: Dict[str, int] = defaultdict(int)
        error_patterns = {
            "connection": re.compile(r"(?i)connection|connect|refused|reset"),
            "timeout": re.compile(r"(?i)timeout|timed?\s*out"),
            "authentication": re.compile(r"(?i)auth|permission|denied|forbidden"),
            "not_found": re.compile(r"(?i)not\s+found|404|missing"),
            "server_error": re.compile(r"(?i)internal|500|server\s+error"),
            "database": re.compile(r"(?i)database|db|sql|query"),
            "memory": re.compile(r"(?i)memory|oom|heap"),
            "io": re.compile(r"(?i)i/o|disk|file|read|write"),
        }

        for entry in error_entries:
            categorized = False
            for category, pattern in error_patterns.items():
                if pattern.search(entry.message):
                    categories[category] += 1
                    categorized = True
                    break
            if not categorized:
                categories["other"] += 1

        return {
            "total_errors": len(error_entries),
            "categories": dict(categories),
            "top_error_messages": [
                {"message": msg, "count": count}
                for msg, count in Counter(
                    e.message[:100] for e in error_entries
                ).most_common(10)
            ],
        }

    def _compute_time_range(
        self, entries: List[LogEntry]
    ) -> Optional[Dict[str, Any]]:
        """Compute the time range of all entries."""
        timestamped = [e for e in entries if e.timestamp is not None]
        if not timestamped:
            return None

        timestamps = [e.timestamp for e in timestamped]
        min_ts = min(timestamps)  # type: ignore
        max_ts = max(timestamps)  # type: ignore
        duration = (max_ts - min_ts).total_seconds()

        return {
            "start": min_ts.isoformat(),
            "end": max_ts.isoformat(),
            "duration_seconds": round(duration, 2),
            "duration_human": self._format_duration(duration),
        }

    @staticmethod
    def _std_dev(values: List[float]) -> float:
        """Calculate standard deviation."""
        if len(values) < 2:
            return 0.0
        mean = sum(values) / len(values)
        variance = sum((v - mean) ** 2 for v in values) / len(values)
        return math.sqrt(variance)

    @staticmethod
    def _format_duration(seconds: float) -> str:
        """Format duration in human-readable form."""
        if seconds < 60:
            return f"{seconds:.1f}s"
        elif seconds < 3600:
            minutes = seconds / 60
            return f"{minutes:.1f}m"
        elif seconds < 86400:
            hours = seconds / 3600
            return f"{hours:.1f}h"
        else:
            days = seconds / 86400
            return f"{days:.1f}d"
