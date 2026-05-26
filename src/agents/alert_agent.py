"""
AlertAgent — Severity classification and threshold-based alerting.

Evaluates log entries and analysis results against configurable thresholds
to generate alerts with appropriate severity levels.
"""

from collections import defaultdict
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Tuple

from src.agents.base import BaseAgent
from src.models.analysis_state import AnalysisState
from src.models.log_entry import LogEntry, Severity


class AlertRule:
    """Represents a single alerting rule with conditions and thresholds."""

    def __init__(
        self,
        name: str,
        condition: str,
        threshold: float,
        severity: str,
        window_seconds: int = 300,
        description: str = "",
    ) -> None:
        self.name = name
        self.condition = condition
        self.threshold = threshold
        self.severity = severity
        self.window_seconds = window_seconds
        self.description = description
        self.triggered_count: int = 0
        self.last_triggered: Optional[datetime] = None

    def to_dict(self) -> Dict[str, Any]:
        """Serialize rule to dictionary."""
        return {
            "name": self.name,
            "condition": self.condition,
            "threshold": self.threshold,
            "severity": self.severity,
            "window_seconds": self.window_seconds,
            "description": self.description,
            "triggered_count": self.triggered_count,
            "last_triggered": str(self.last_triggered) if self.last_triggered else None,
        }


class Alert:
    """Represents a triggered alert."""

    def __init__(
        self,
        rule_name: str,
        severity: str,
        message: str,
        timestamp: Optional[datetime] = None,
        context: Optional[Dict[str, Any]] = None,
    ) -> None:
        self.rule_name = rule_name
        self.severity = severity
        self.message = message
        self.timestamp = timestamp or datetime.now()
        self.context = context or {}

    def to_dict(self) -> Dict[str, Any]:
        """Serialize alert to dictionary."""
        return {
            "rule_name": self.rule_name,
            "severity": self.severity,
            "message": self.message,
            "timestamp": self.timestamp.isoformat(),
            "context": self.context,
        }


DEFAULT_RULES = [
    AlertRule(
        name="high_error_rate",
        condition="error_rate_percent",
        threshold=10.0,
        severity="high",
        window_seconds=300,
        description="Error rate exceeds 10% of total log entries",
    ),
    AlertRule(
        name="critical_errors",
        condition="critical_count",
        threshold=1.0,
        severity="critical",
        window_seconds=60,
        description="Any critical-level log entries detected",
    ),
    AlertRule(
        name="error_burst",
        condition="error_burst_count",
        threshold=5.0,
        severity="high",
        window_seconds=60,
        description="More than 5 errors within 60 seconds",
    ),
    AlertRule(
        name="high_latency",
        condition="p99_latency_ms",
        threshold=5000.0,
        severity="medium",
        window_seconds=300,
        description="P99 latency exceeds 5 seconds",
    ),
    AlertRule(
        name="service_down",
        condition="connection_refused_count",
        threshold=3.0,
        severity="critical",
        window_seconds=120,
        description="Multiple connection refused errors indicate service down",
    ),
    AlertRule(
        name="disk_space",
        condition="disk_error_count",
        threshold=1.0,
        severity="high",
        window_seconds=600,
        description="Disk space or I/O errors detected",
    ),
    AlertRule(
        name="auth_failures",
        condition="auth_failure_count",
        threshold=5.0,
        severity="medium",
        window_seconds=300,
        description="Multiple authentication failures may indicate brute force",
    ),
    AlertRule(
        name="oom_detected",
        condition="oom_count",
        threshold=1.0,
        severity="critical",
        window_seconds=60,
        description="Out of memory condition detected",
    ),
]


class AlertAgent(BaseAgent):
    """Agent that evaluates conditions and generates alerts.

    Applies configurable rules against log data and analysis results
    to produce severity-classified alerts.
    """

    def __init__(self, config: Optional[Dict[str, Any]] = None) -> None:
        super().__init__(name="alert", config=config)
        self._rules: List[AlertRule] = self._load_rules()
        self._cooldown_seconds: int = self.config.get("cooldown_seconds", 60)
        self._max_alerts: int = self.config.get("max_alerts", 100)

    def _load_rules(self) -> List[AlertRule]:
        """Load alerting rules from config or use defaults."""
        custom_rules = self.config.get("rules", [])
        if custom_rules:
            rules = []
            for rule_cfg in custom_rules:
                rules.append(AlertRule(
                    name=rule_cfg.get("name", "custom"),
                    condition=rule_cfg.get("condition", ""),
                    threshold=float(rule_cfg.get("threshold", 1.0)),
                    severity=rule_cfg.get("severity", "medium"),
                    window_seconds=int(rule_cfg.get("window_seconds", 300)),
                    description=rule_cfg.get("description", ""),
                ))
            return rules
        return list(DEFAULT_RULES)

    async def analyze(self, state: AnalysisState) -> Dict[str, Any]:
        """Evaluate alerting rules against current state.

        Args:
            state: Analysis state with parsed entries and other agent results.

        Returns:
            Dictionary with triggered alerts, rule evaluations, and summary.
        """
        entries = state.log_entries
        alerts: List[Alert] = []

        # Compute metrics needed for rule evaluation
        metrics = self._compute_alert_metrics(entries)

        # Evaluate each rule
        rule_evaluations: List[Dict[str, Any]] = []
        for rule in self._rules:
            triggered, alert = self._evaluate_rule(rule, metrics, entries)
            evaluation = {
                "rule": rule.to_dict(),
                "triggered": triggered,
                "current_value": metrics.get(rule.condition, 0),
            }
            rule_evaluations.append(evaluation)
            if triggered and alert:
                alerts.append(alert)

        # Check for anomaly-based alerts from other agents
        anomaly_alerts = self._check_anomaly_results(state)
        alerts.extend(anomaly_alerts)

        # Sort alerts by severity
        severity_order = {"critical": 4, "high": 3, "medium": 2, "low": 1}
        alerts.sort(
            key=lambda a: severity_order.get(a.severity, 0), reverse=True
        )

        # Limit alerts
        alerts = alerts[:self._max_alerts]

        # Build summary
        alert_summary = self._build_alert_summary(alerts)

        state.agent_results["alert"] = {
            "alerts": [a.to_dict() for a in alerts],
            "total_alerts": len(alerts),
        }

        return {
            "alerts": [a.to_dict() for a in alerts],
            "total_alerts": len(alerts),
            "rule_evaluations": rule_evaluations,
            "alert_summary": alert_summary,
            "metrics_evaluated": metrics,
        }

    def _compute_alert_metrics(
        self, entries: List[LogEntry]
    ) -> Dict[str, float]:
        """Compute metrics needed for rule evaluation."""
        total = len(entries) if entries else 1
        metrics: Dict[str, float] = {}

        # Error rate
        error_count = sum(
            1 for e in entries
            if e.severity in (Severity.ERROR, Severity.CRITICAL)
        )
        metrics["error_rate_percent"] = (error_count / total) * 100

        # Critical count
        critical_count = sum(
            1 for e in entries if e.severity == Severity.CRITICAL
        )
        metrics["critical_count"] = float(critical_count)

        # Error burst detection (max errors in any 60s window)
        metrics["error_burst_count"] = float(
            self._max_errors_in_window(entries, window_seconds=60)
        )

        # Latency metrics (from metadata)
        latencies = self._extract_latencies(entries)
        if latencies:
            sorted_lat = sorted(latencies)
            p99_idx = int(len(sorted_lat) * 0.99)
            metrics["p99_latency_ms"] = sorted_lat[min(p99_idx, len(sorted_lat) - 1)]
        else:
            metrics["p99_latency_ms"] = 0.0

        # Connection refused count
        import re
        conn_refused = sum(
            1 for e in entries
            if re.search(r"(?i)connection\s+refused", e.message)
        )
        metrics["connection_refused_count"] = float(conn_refused)

        # Disk errors
        disk_errors = sum(
            1 for e in entries
            if re.search(r"(?i)no\s+space|disk\s+full|I/O\s+error", e.message)
        )
        metrics["disk_error_count"] = float(disk_errors)

        # Auth failures
        auth_failures = sum(
            1 for e in entries
            if re.search(r"(?i)auth.*fail|invalid.*(?:token|password|credential)", e.message)
        )
        metrics["auth_failure_count"] = float(auth_failures)

        # OOM
        oom_count = sum(
            1 for e in entries
            if re.search(r"(?i)out\s+of\s+memory|OOM|heap\s+space", e.message)
        )
        metrics["oom_count"] = float(oom_count)

        return metrics

    def _evaluate_rule(
        self,
        rule: AlertRule,
        metrics: Dict[str, float],
        entries: List[LogEntry],
    ) -> Tuple[bool, Optional[Alert]]:
        """Evaluate a single alerting rule against computed metrics."""
        current_value = metrics.get(rule.condition, 0.0)

        if current_value >= rule.threshold:
            # Check cooldown
            now = datetime.now()
            if rule.last_triggered:
                elapsed = (now - rule.last_triggered).total_seconds()
                if elapsed < self._cooldown_seconds:
                    return False, None

            rule.triggered_count += 1
            rule.last_triggered = now

            alert = Alert(
                rule_name=rule.name,
                severity=rule.severity,
                message=f"{rule.description} (current: {current_value:.1f}, threshold: {rule.threshold:.1f})",
                timestamp=now,
                context={
                    "condition": rule.condition,
                    "current_value": current_value,
                    "threshold": rule.threshold,
                    "window_seconds": rule.window_seconds,
                },
            )
            return True, alert

        return False, None

    def _check_anomaly_results(self, state: AnalysisState) -> List[Alert]:
        """Generate alerts from anomaly detection results."""
        alerts: List[Alert] = []
        anomaly_results = state.agent_results.get("anomaly", {})
        anomalies = anomaly_results.get("anomalies", [])

        for anomaly in anomalies:
            if anomaly.get("severity") in ("critical", "high"):
                alerts.append(Alert(
                    rule_name=f"anomaly_{anomaly.get('type', 'unknown')}",
                    severity=anomaly["severity"],
                    message=anomaly.get("description", "Anomaly detected"),
                    context=anomaly,
                ))

        return alerts

    def _max_errors_in_window(
        self, entries: List[LogEntry], window_seconds: int
    ) -> int:
        """Find the maximum number of errors in any sliding window."""
        error_entries = [
            e for e in entries
            if e.severity in (Severity.ERROR, Severity.CRITICAL) and e.timestamp
        ]
        if not error_entries:
            return 0

        error_entries.sort(key=lambda e: e.timestamp)  # type: ignore
        max_count = 0
        window = timedelta(seconds=window_seconds)

        for i, entry in enumerate(error_entries):
            count = 0
            for j in range(i, len(error_entries)):
                if (error_entries[j].timestamp - entry.timestamp) <= window:  # type: ignore
                    count += 1
                else:
                    break
            max_count = max(max_count, count)

        return max_count

    def _extract_latencies(self, entries: List[LogEntry]) -> List[float]:
        """Extract latency values from log entry metadata."""
        latencies: List[float] = []
        import re

        for entry in entries:
            # Check metadata for request_time
            if "request_time" in entry.metadata:
                try:
                    latencies.append(float(entry.metadata["request_time"]) * 1000)
                except (ValueError, TypeError):
                    pass

            # Check message for duration patterns
            duration_match = re.search(
                r"(\d+(?:\.\d+)?)\s*ms", entry.message
            )
            if duration_match:
                latencies.append(float(duration_match.group(1)))

            duration_match_s = re.search(
                r"(\d+(?:\.\d+)?)\s*(?:s|sec)\b", entry.message
            )
            if duration_match_s:
                latencies.append(float(duration_match_s.group(1)) * 1000)

        return latencies

    def _build_alert_summary(self, alerts: List[Alert]) -> Dict[str, Any]:
        """Build a summary of all triggered alerts."""
        severity_counts: Dict[str, int] = defaultdict(int)
        rule_counts: Dict[str, int] = defaultdict(int)

        for alert in alerts:
            severity_counts[alert.severity] += 1
            rule_counts[alert.rule_name] += 1

        return {
            "total_alerts": len(alerts),
            "by_severity": dict(severity_counts),
            "by_rule": dict(rule_counts),
            "has_critical": severity_counts.get("critical", 0) > 0,
            "has_high": severity_counts.get("high", 0) > 0,
        }
