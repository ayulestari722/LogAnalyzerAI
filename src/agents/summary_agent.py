"""
SummaryAgent — Final report aggregation from all agents.

Collects results from all other agents and produces a unified
analysis report with key findings, recommendations, and overall health score.
"""

from collections import defaultdict
from datetime import datetime
from typing import Any, Dict, List, Optional

from src.agents.base import BaseAgent
from src.models.analysis_state import AnalysisState
from src.models.log_entry import Severity


class SummaryAgent(BaseAgent):
    """Agent that aggregates results from all other agents into a final report.

    Runs last in the pipeline after all other agents have completed.
    Produces a unified summary with:
    - Overall health score (0-100)
    - Key findings ranked by severity
    - Recommendations for action
    - Executive summary text
    """

    def __init__(self, config: Optional[Dict[str, Any]] = None) -> None:
        super().__init__(name="summary", config=config)
        self._health_weights: Dict[str, float] = self.config.get("health_weights", {
            "error_rate": 0.30,
            "anomaly_count": 0.25,
            "alert_severity": 0.25,
            "pattern_diversity": 0.10,
            "correlation_issues": 0.10,
        })

    async def analyze(self, state: AnalysisState) -> Dict[str, Any]:
        """Aggregate all agent results into a final summary report.

        Args:
            state: Analysis state with results from all other agents.

        Returns:
            Dictionary with unified report, health score, and recommendations.
        """
        agent_results = state.agent_results

        # Compute overall health score
        health_score = self._compute_health_score(agent_results, state)

        # Extract key findings
        key_findings = self._extract_key_findings(agent_results)

        # Generate recommendations
        recommendations = self._generate_recommendations(agent_results, health_score)

        # Build executive summary text
        executive_summary = self._build_executive_summary(
            state, health_score, key_findings
        )

        # Compile agent status overview
        agent_overview = self._build_agent_overview(agent_results)

        # Build timeline of significant events
        timeline = self._build_event_timeline(agent_results)

        report = {
            "health_score": health_score,
            "health_status": self._health_status_label(health_score),
            "executive_summary": executive_summary,
            "key_findings": key_findings,
            "recommendations": recommendations,
            "agent_overview": agent_overview,
            "event_timeline": timeline[:20],
            "total_entries_analyzed": len(state.log_entries),
            "sources_analyzed": list(set(e.source for e in state.log_entries)),
            "analysis_timestamp": datetime.now().isoformat(),
            "report_metadata": {
                "agents_completed": len(agent_results),
                "agents_expected": 6,
                "pipeline_status": "complete" if len(agent_results) >= 5 else "partial",
            },
        }

        state.agent_results["summary"] = report
        state.is_complete = True

        return report

    def _compute_health_score(
        self, agent_results: Dict[str, Any], state: AnalysisState
    ) -> float:
        """Compute overall health score from 0 (critical) to 100 (healthy)."""
        score = 100.0

        # Factor 1: Error rate penalty
        metrics = agent_results.get("metrics", {})
        severity_info = metrics.get("severity", {})
        error_rate = severity_info.get("error_rate_percent", 0)
        error_penalty = min(error_rate * 3, 30)  # Max 30 point penalty
        score -= error_penalty * self._health_weights.get("error_rate", 0.30) / 0.30

        # Factor 2: Anomaly count penalty
        anomaly_info = agent_results.get("anomaly", {})
        anomaly_count = anomaly_info.get("total_anomalies", 0)
        anomaly_penalty = min(anomaly_count * 2, 25)
        score -= anomaly_penalty * self._health_weights.get("anomaly_count", 0.25) / 0.25

        # Factor 3: Alert severity penalty
        alert_info = agent_results.get("alert", {})
        alerts = alert_info.get("alerts", [])
        alert_penalty = 0.0
        for alert in alerts:
            severity = alert.get("severity", "low")
            if severity == "critical":
                alert_penalty += 10
            elif severity == "high":
                alert_penalty += 5
            elif severity == "medium":
                alert_penalty += 2
            else:
                alert_penalty += 0.5
        alert_penalty = min(alert_penalty, 25)
        score -= alert_penalty * self._health_weights.get("alert_severity", 0.25) / 0.25

        # Factor 4: Correlation issues
        correlation_info = agent_results.get("correlation", {})
        causal_chains = correlation_info.get("causal_chains", [])
        chain_penalty = min(len(causal_chains) * 3, 10)
        score -= chain_penalty * self._health_weights.get("correlation_issues", 0.10) / 0.10

        return max(0.0, min(100.0, round(score, 1)))

    def _extract_key_findings(
        self, agent_results: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """Extract and rank key findings from all agent results."""
        findings: List[Dict[str, Any]] = []

        # From anomaly agent
        anomaly_info = agent_results.get("anomaly", {})
        anomalies = anomaly_info.get("anomalies", [])
        for anomaly in anomalies[:5]:
            findings.append({
                "source": "anomaly_detection",
                "severity": anomaly.get("severity", "medium"),
                "title": f"Anomaly: {anomaly.get('type', 'unknown')}",
                "description": anomaly.get("description", ""),
                "timestamp": anomaly.get("timestamp"),
            })

        # From alert agent
        alert_info = agent_results.get("alert", {})
        alerts = alert_info.get("alerts", [])
        for alert in alerts[:5]:
            findings.append({
                "source": "alerting",
                "severity": alert.get("severity", "medium"),
                "title": f"Alert: {alert.get('rule_name', 'unknown')}",
                "description": alert.get("message", ""),
                "timestamp": alert.get("timestamp"),
            })

        # From pattern agent
        pattern_info = agent_results.get("pattern", {})
        error_patterns = pattern_info.get("error_patterns", {})
        for pattern_name, occurrences in list(error_patterns.items())[:3]:
            if occurrences:
                findings.append({
                    "source": "pattern_analysis",
                    "severity": "medium",
                    "title": f"Error pattern: {pattern_name}",
                    "description": f"Detected {len(occurrences)} occurrences of {pattern_name}",
                    "timestamp": None,
                })

        # From metrics agent
        metrics = agent_results.get("metrics", {})
        error_breakdown = metrics.get("error_breakdown", {})
        if error_breakdown.get("total_errors", 0) > 0:
            findings.append({
                "source": "metrics",
                "severity": "high" if error_breakdown["total_errors"] > 10 else "medium",
                "title": f"Total errors: {error_breakdown['total_errors']}",
                "description": f"Error categories: {error_breakdown.get('categories', {})}",
                "timestamp": None,
            })

        # Sort by severity
        severity_order = {"critical": 4, "high": 3, "medium": 2, "low": 1}
        findings.sort(
            key=lambda f: severity_order.get(f["severity"], 0), reverse=True
        )

        return findings[:15]

    def _generate_recommendations(
        self, agent_results: Dict[str, Any], health_score: float
    ) -> List[Dict[str, Any]]:
        """Generate actionable recommendations based on findings."""
        recommendations: List[Dict[str, Any]] = []

        # Based on health score
        if health_score < 50:
            recommendations.append({
                "priority": "critical",
                "action": "Immediate investigation required",
                "reason": f"System health score is critically low ({health_score}/100)",
                "category": "general",
            })

        # Based on error patterns
        alert_info = agent_results.get("alert", {})
        metrics_evaluated = alert_info.get("metrics_evaluated", {})

        if metrics_evaluated.get("connection_refused_count", 0) > 0:
            recommendations.append({
                "priority": "high",
                "action": "Check service connectivity and dependencies",
                "reason": "Connection refused errors detected — downstream service may be down",
                "category": "infrastructure",
            })

        if metrics_evaluated.get("oom_count", 0) > 0:
            recommendations.append({
                "priority": "critical",
                "action": "Increase memory allocation or investigate memory leaks",
                "reason": "Out-of-memory conditions detected",
                "category": "resources",
            })

        if metrics_evaluated.get("auth_failure_count", 0) >= 5:
            recommendations.append({
                "priority": "medium",
                "action": "Review authentication logs for potential brute force attempts",
                "reason": "Multiple authentication failures detected",
                "category": "security",
            })

        if metrics_evaluated.get("disk_error_count", 0) > 0:
            recommendations.append({
                "priority": "high",
                "action": "Check disk space and I/O health",
                "reason": "Disk-related errors detected",
                "category": "infrastructure",
            })

        # Based on metrics
        metrics = agent_results.get("metrics", {})
        latency = metrics.get("latency", {})
        if latency.get("available") and latency.get("percentiles", {}).get("p99", 0) > 5000:
            recommendations.append({
                "priority": "medium",
                "action": "Investigate high-latency requests",
                "reason": f"P99 latency is {latency['percentiles']['p99']:.0f}ms",
                "category": "performance",
            })

        # Based on anomalies
        anomaly_info = agent_results.get("anomaly", {})
        anomaly_types = anomaly_info.get("anomaly_types", {})
        if anomaly_types.get("time_gap", 0) > 0:
            recommendations.append({
                "priority": "medium",
                "action": "Investigate log gaps — possible service interruptions",
                "reason": "Unexpected gaps detected in log timeline",
                "category": "reliability",
            })

        return recommendations

    def _build_executive_summary(
        self,
        state: AnalysisState,
        health_score: float,
        key_findings: List[Dict[str, Any]],
    ) -> str:
        """Build a human-readable executive summary."""
        total_entries = len(state.log_entries)
        sources = list(set(e.source for e in state.log_entries))
        status = self._health_status_label(health_score)

        critical_findings = [f for f in key_findings if f["severity"] == "critical"]
        high_findings = [f for f in key_findings if f["severity"] == "high"]

        summary_parts = [
            f"Analysis of {total_entries} log entries from {len(sources)} source(s).",
            f"Overall health: {status} (score: {health_score}/100).",
        ]

        if critical_findings:
            summary_parts.append(
                f"CRITICAL: {len(critical_findings)} critical finding(s) require immediate attention."
            )
        if high_findings:
            summary_parts.append(
                f"HIGH: {len(high_findings)} high-severity finding(s) detected."
            )

        if health_score >= 80:
            summary_parts.append("System appears to be operating normally.")
        elif health_score >= 60:
            summary_parts.append("Some issues detected that warrant monitoring.")
        elif health_score >= 40:
            summary_parts.append("Multiple issues detected — investigation recommended.")
        else:
            summary_parts.append("System is in a degraded state — immediate action required.")

        return " ".join(summary_parts)

    def _build_agent_overview(
        self, agent_results: Dict[str, Any]
    ) -> Dict[str, Dict[str, Any]]:
        """Build overview of each agent's contribution."""
        overview: Dict[str, Dict[str, Any]] = {}

        agent_summaries = {
            "parser": lambda r: {"parsed_entries": r.get("parsed_entries", 0)},
            "anomaly": lambda r: {"anomalies_found": r.get("total_anomalies", 0)},
            "pattern": lambda r: {"patterns_found": r.get("total_patterns", 0)},
            "correlation": lambda r: {"correlations": r.get("total_correlated_events", 0)},
            "alert": lambda r: {"alerts_triggered": r.get("total_alerts", 0)},
            "metrics": lambda r: {"total_entries": r.get("total_entries", 0)},
        }

        for agent_name, summarizer in agent_summaries.items():
            result = agent_results.get(agent_name, {})
            overview[agent_name] = {
                "status": "completed" if result else "not_run",
                "summary": summarizer(result) if result else {},
            }

        return overview

    def _build_event_timeline(
        self, agent_results: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """Build a timeline of significant events from all agents."""
        events: List[Dict[str, Any]] = []

        # Add anomaly events
        anomaly_info = agent_results.get("anomaly", {})
        for anomaly in anomaly_info.get("anomalies", [])[:10]:
            if anomaly.get("timestamp"):
                events.append({
                    "timestamp": anomaly["timestamp"],
                    "type": "anomaly",
                    "severity": anomaly.get("severity", "medium"),
                    "description": anomaly.get("description", "")[:100],
                })

        # Add alert events
        alert_info = agent_results.get("alert", {})
        for alert in alert_info.get("alerts", [])[:10]:
            events.append({
                "timestamp": alert.get("timestamp", ""),
                "type": "alert",
                "severity": alert.get("severity", "medium"),
                "description": alert.get("message", "")[:100],
            })

        # Sort by timestamp where possible
        events.sort(key=lambda e: str(e.get("timestamp", "")))

        return events

    @staticmethod
    def _health_status_label(score: float) -> str:
        """Convert health score to human-readable status label."""
        if score >= 90:
            return "HEALTHY"
        elif score >= 75:
            return "GOOD"
        elif score >= 60:
            return "FAIR"
        elif score >= 40:
            return "DEGRADED"
        elif score >= 20:
            return "POOR"
        else:
            return "CRITICAL"
