"""Internal metrics collection for pipeline performance tracking."""

from __future__ import annotations

import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any


@dataclass
class TimingRecord:
    """Single timing measurement."""
    name: str
    start_time: float
    end_time: float = 0.0
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def duration(self) -> float:
        """Duration in seconds."""
        if self.end_time == 0.0:
            return time.time() - self.start_time
        return self.end_time - self.start_time

    @property
    def duration_ms(self) -> float:
        """Duration in milliseconds."""
        return self.duration * 1000


class MetricsCollector:
    """Collects and aggregates pipeline execution metrics.

    Tracks timing, counters, and gauges for each agent and the orchestrator.
    """

    def __init__(self):
        self._timings: dict[str, list[TimingRecord]] = defaultdict(list)
        self._counters: dict[str, int] = defaultdict(int)
        self._gauges: dict[str, float] = {}
        self._active_timers: dict[str, TimingRecord] = {}
        self._start_time: float = time.time()

    def start_timer(self, name: str, **metadata: Any) -> None:
        """Start a named timer."""
        record = TimingRecord(name=name, start_time=time.time(), metadata=metadata)
        self._active_timers[name] = record

    def stop_timer(self, name: str) -> float:
        """Stop a named timer and return duration in seconds."""
        if name not in self._active_timers:
            return 0.0
        record = self._active_timers.pop(name)
        record.end_time = time.time()
        self._timings[name].append(record)
        return record.duration

    def increment(self, name: str, amount: int = 1) -> None:
        """Increment a counter."""
        self._counters[name] += amount

    def set_gauge(self, name: str, value: float) -> None:
        """Set a gauge value."""
        self._gauges[name] = value

    def get_counter(self, name: str) -> int:
        """Get current counter value."""
        return self._counters.get(name, 0)

    def get_gauge(self, name: str) -> float:
        """Get current gauge value."""
        return self._gauges.get(name, 0.0)

    def get_timing_stats(self, name: str) -> dict[str, float]:
        """Get timing statistics for a named operation."""
        records = self._timings.get(name, [])
        if not records:
            return {"count": 0, "min": 0, "max": 0, "avg": 0, "total": 0}

        durations = [r.duration for r in records]
        return {
            "count": len(durations),
            "min": min(durations),
            "max": max(durations),
            "avg": sum(durations) / len(durations),
            "total": sum(durations),
        }

    def get_all_timings(self) -> dict[str, dict[str, float]]:
        """Get timing stats for all tracked operations."""
        return {name: self.get_timing_stats(name) for name in self._timings}

    def get_total_duration(self) -> float:
        """Get total elapsed time since collector creation."""
        return time.time() - self._start_time

    def get_summary(self) -> dict[str, Any]:
        """Get complete metrics summary."""
        return {
            "total_duration_seconds": round(self.get_total_duration(), 3),
            "timings": {
                name: {k: round(v, 4) if isinstance(v, float) else v
                       for k, v in stats.items()}
                for name, stats in self.get_all_timings().items()
            },
            "counters": dict(self._counters),
            "gauges": {k: round(v, 4) for k, v in self._gauges.items()},
        }

    def reset(self) -> None:
        """Reset all metrics."""
        self._timings.clear()
        self._counters.clear()
        self._gauges.clear()
        self._active_timers.clear()
        self._start_time = time.time()
