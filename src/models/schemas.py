"""
Output schemas: JSON, Markdown, and SARIF format definitions.

Defines the structure of analysis output in multiple formats for
integration with different tools and reporting systems.
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional


@dataclass
class JsonReportSchema:
    """Schema for JSON output format.

    Represents the complete analysis report in a structured JSON format
    suitable for programmatic consumption and API responses.
    """

    version: str = "1.0.0"
    schema_type: str = "log_analysis_report"
    generated_at: str = field(default_factory=lambda: datetime.now().isoformat())
    tool_name: str = "LogAnalyzerAI"
    tool_version: str = "0.1.0"

    # Report sections
    summary: Dict[str, Any] = field(default_factory=dict)
    metrics: Dict[str, Any] = field(default_factory=dict)
    anomalies: List[Dict[str, Any]] = field(default_factory=list)
    alerts: List[Dict[str, Any]] = field(default_factory=list)
    patterns: Dict[str, Any] = field(default_factory=dict)
    correlations: List[Dict[str, Any]] = field(default_factory=list)
    recommendations: List[Dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """Serialize to dictionary for JSON output."""
        return {
            "$schema": "https://loganalyzerai.dev/schemas/report-v1.json",
            "version": self.version,
            "schema_type": self.schema_type,
            "generated_at": self.generated_at,
            "tool": {
                "name": self.tool_name,
                "version": self.tool_version,
            },
            "report": {
                "summary": self.summary,
                "metrics": self.metrics,
                "anomalies": self.anomalies,
                "alerts": self.alerts,
                "patterns": self.patterns,
                "correlations": self.correlations,
                "recommendations": self.recommendations,
            },
        }

    @classmethod
    def from_analysis_results(cls, results: Dict[str, Any]) -> "JsonReportSchema":
        """Create a JsonReportSchema from raw analysis results."""
        schema = cls()
        schema.summary = results.get("summary", {})
        schema.metrics = results.get("metrics", {})
        schema.anomalies = results.get("anomaly", {}).get("anomalies", [])
        schema.alerts = results.get("alert", {}).get("alerts", [])
        schema.patterns = results.get("pattern", {})
        schema.correlations = results.get("correlation", {}).get("correlation_groups", [])
        schema.recommendations = results.get("summary", {}).get("recommendations", [])
        return schema


@dataclass
class MarkdownReportSchema:
    """Schema for Markdown output format.

    Defines the structure of a human-readable Markdown report with
    sections, tables, and formatted findings.
    """

    title: str = "Log Analysis Report"
    generated_at: str = field(default_factory=lambda: datetime.now().isoformat())
    sections: List[Dict[str, Any]] = field(default_factory=list)

    def add_section(
        self,
        heading: str,
        content: str,
        level: int = 2,
        subsections: Optional[List[Dict[str, Any]]] = None,
    ) -> None:
        """Add a section to the report."""
        self.sections.append({
            "heading": heading,
            "content": content,
            "level": level,
            "subsections": subsections or [],
        })

    def render(self) -> str:
        """Render the complete Markdown report."""
        lines: List[str] = []
        lines.append(f"# {self.title}")
        lines.append("")
        lines.append(f"*Generated: {self.generated_at}*")
        lines.append("")

        for section in self.sections:
            prefix = "#" * section["level"]
            lines.append(f"{prefix} {section['heading']}")
            lines.append("")
            lines.append(section["content"])
            lines.append("")

            for subsection in section.get("subsections", []):
                sub_prefix = "#" * (section["level"] + 1)
                lines.append(f"{sub_prefix} {subsection['heading']}")
                lines.append("")
                lines.append(subsection["content"])
                lines.append("")

        return "\n".join(lines)

    @classmethod
    def from_analysis_results(cls, results: Dict[str, Any]) -> "MarkdownReportSchema":
        """Create a MarkdownReportSchema from raw analysis results."""
        schema = cls()

        # Summary section
        summary = results.get("summary", {})
        if summary:
            health_score = summary.get("health_score", "N/A")
            health_status = summary.get("health_status", "UNKNOWN")
            exec_summary = summary.get("executive_summary", "No summary available.")
            schema.add_section(
                "Executive Summary",
                f"**Health Score:** {health_score}/100 ({health_status})\n\n{exec_summary}",
            )

        # Key Findings
        findings = summary.get("key_findings", [])
        if findings:
            findings_text = ""
            for i, finding in enumerate(findings[:10], 1):
                severity_badge = f"[{finding['severity'].upper()}]"
                findings_text += f"{i}. {severity_badge} **{finding['title']}**\n"
                findings_text += f"   {finding['description']}\n\n"
            schema.add_section("Key Findings", findings_text)

        # Metrics
        metrics = results.get("metrics", {})
        if metrics:
            severity_info = metrics.get("severity", {})
            throughput = metrics.get("throughput", {})
            metrics_text = "| Metric | Value |\n|--------|-------|\n"
            metrics_text += f"| Total Entries | {metrics.get('total_entries', 0)} |\n"
            metrics_text += f"| Error Rate | {severity_info.get('error_rate_percent', 0)}% |\n"
            metrics_text += f"| Entries/sec | {throughput.get('entries_per_second', 0)} |\n"
            metrics_text += f"| Peak/sec | {throughput.get('peak_per_second', 0)} |\n"

            latency = metrics.get("latency", {})
            if latency.get("available"):
                percentiles = latency.get("percentiles", {})
                metrics_text += f"| P50 Latency | {percentiles.get('p50', 'N/A')}ms |\n"
                metrics_text += f"| P99 Latency | {percentiles.get('p99', 'N/A')}ms |\n"

            schema.add_section("Metrics", metrics_text)

        # Alerts
        alert_info = results.get("alert", {})
        alerts = alert_info.get("alerts", [])
        if alerts:
            alerts_text = ""
            for alert in alerts[:10]:
                severity = alert.get("severity", "unknown").upper()
                alerts_text += f"- **[{severity}]** {alert.get('message', '')}\n"
            schema.add_section("Alerts", alerts_text)

        # Recommendations
        recommendations = summary.get("recommendations", [])
        if recommendations:
            rec_text = ""
            for rec in recommendations:
                priority = rec.get("priority", "medium").upper()
                rec_text += f"- **[{priority}]** {rec.get('action', '')}\n"
                rec_text += f"  *Reason:* {rec.get('reason', '')}\n\n"
            schema.add_section("Recommendations", rec_text)

        return schema


@dataclass
class SarifResult:
    """A single SARIF result (finding)."""

    rule_id: str
    message: str
    level: str = "warning"  # note, warning, error
    location: Optional[Dict[str, Any]] = None
    properties: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Serialize to SARIF result format."""
        result: Dict[str, Any] = {
            "ruleId": self.rule_id,
            "level": self.level,
            "message": {"text": self.message},
        }
        if self.location:
            result["locations"] = [self.location]
        if self.properties:
            result["properties"] = self.properties
        return result


@dataclass
class SarifReportSchema:
    """Schema for SARIF (Static Analysis Results Interchange Format) output.

    SARIF is a standard format for static analysis tools, useful for
    integration with CI/CD pipelines and code scanning tools.
    """

    version: str = "2.1.0"
    schema_uri: str = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"
    tool_name: str = "LogAnalyzerAI"
    tool_version: str = "0.1.0"
    results: List[SarifResult] = field(default_factory=list)
    rules: List[Dict[str, Any]] = field(default_factory=list)

    def add_result(
        self,
        rule_id: str,
        message: str,
        level: str = "warning",
        file_path: Optional[str] = None,
        line_number: Optional[int] = None,
        properties: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Add a result to the SARIF report."""
        location = None
        if file_path:
            location = {
                "physicalLocation": {
                    "artifactLocation": {"uri": file_path},
                }
            }
            if line_number:
                location["physicalLocation"]["region"] = {
                    "startLine": line_number
                }

        self.results.append(SarifResult(
            rule_id=rule_id,
            message=message,
            level=level,
            location=location,
            properties=properties or {},
        ))

    def to_dict(self) -> Dict[str, Any]:
        """Serialize to complete SARIF format."""
        return {
            "$schema": self.schema_uri,
            "version": self.version,
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": self.tool_name,
                            "version": self.tool_version,
                            "informationUri": "https://github.com/ayulestari722/LogAnalyzerAI",
                            "rules": self.rules,
                        }
                    },
                    "results": [r.to_dict() for r in self.results],
                }
            ],
        }

    @classmethod
    def from_analysis_results(
        cls, results: Dict[str, Any], source_file: Optional[str] = None
    ) -> "SarifReportSchema":
        """Create a SarifReportSchema from raw analysis results."""
        schema = cls()

        # Define rules
        schema.rules = [
            {
                "id": "LOG001",
                "name": "AnomalyDetected",
                "shortDescription": {"text": "Statistical anomaly detected in log data"},
                "defaultConfiguration": {"level": "warning"},
            },
            {
                "id": "LOG002",
                "name": "ErrorBurst",
                "shortDescription": {"text": "Burst of error-level entries detected"},
                "defaultConfiguration": {"level": "error"},
            },
            {
                "id": "LOG003",
                "name": "AlertTriggered",
                "shortDescription": {"text": "Alerting threshold exceeded"},
                "defaultConfiguration": {"level": "warning"},
            },
            {
                "id": "LOG004",
                "name": "CausalChain",
                "shortDescription": {"text": "Escalating error chain detected"},
                "defaultConfiguration": {"level": "error"},
            },
        ]

        # Add anomaly results
        anomaly_info = results.get("anomaly", {})
        for anomaly in anomaly_info.get("anomalies", []):
            severity_map = {"critical": "error", "high": "error", "medium": "warning", "low": "note"}
            level = severity_map.get(anomaly.get("severity", "medium"), "warning")
            schema.add_result(
                rule_id="LOG001",
                message=anomaly.get("description", "Anomaly detected"),
                level=level,
                file_path=source_file,
                line_number=anomaly.get("line_number"),
                properties={"anomaly_type": anomaly.get("type", "unknown")},
            )

        # Add alert results
        alert_info = results.get("alert", {})
        for alert in alert_info.get("alerts", []):
            severity_map = {"critical": "error", "high": "error", "medium": "warning", "low": "note"}
            level = severity_map.get(alert.get("severity", "medium"), "warning")
            schema.add_result(
                rule_id="LOG003",
                message=alert.get("message", "Alert triggered"),
                level=level,
                file_path=source_file,
                properties={"rule_name": alert.get("rule_name", "unknown")},
            )

        return schema
