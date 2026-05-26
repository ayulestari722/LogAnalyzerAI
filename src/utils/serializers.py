"""Output serializers for JSON, Markdown, and SARIF formats."""

from __future__ import annotations

import json
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from typing import Any


class BaseSerializer(ABC):
    """Abstract base for output serializers."""

    @abstractmethod
    def serialize(self, results: dict[str, Any]) -> str:
        """Serialize analysis results to string output."""
        ...

    @abstractmethod
    def get_content_type(self) -> str:
        """Return MIME content type."""
        ...

    @abstractmethod
    def get_extension(self) -> str:
        """Return file extension (without dot)."""
        ...


class JSONSerializer(BaseSerializer):
    """Serialize results to formatted JSON."""

    def __init__(self, indent: int = 2, include_metadata: bool = True):
        self.indent = indent
        self.include_metadata = include_metadata

    def serialize(self, results: dict[str, Any]) -> str:
        output = {}
        if self.include_metadata:
            output["metadata"] = {
                "tool": "LogAnalyzerAI",
                "version": "0.1.0",
                "generated_at": datetime.now(timezone.utc).isoformat(),
                "format": "json",
            }
        output["summary"] = results.get("summary", {})
        output["findings"] = results.get("findings", [])
        output["metrics"] = results.get("metrics", {})
        output["agents"] = results.get("agent_results", {})
        return json.dumps(output, indent=self.indent, default=str, ensure_ascii=False)

    def get_content_type(self) -> str:
        return "application/json"

    def get_extension(self) -> str:
        return "json"


class MarkdownSerializer(BaseSerializer):
    """Serialize results to Markdown report."""

    def __init__(self, include_toc: bool = True, max_examples: int = 5):
        self.include_toc = include_toc
        self.max_examples = max_examples

    def serialize(self, results: dict[str, Any]) -> str:
        lines: list[str] = []
        summary = results.get("summary", {})
        findings = results.get("findings", [])
        metrics = results.get("metrics", {})
        agent_results = results.get("agent_results", {})

        # Header
        lines.append("# LogAnalyzerAI — Analysis Report")
        lines.append("")
        lines.append(f"**Generated:** {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}")
        lines.append(f"**Total Findings:** {len(findings)}")
        lines.append(f"**Overall Score:** {summary.get('score', 0):.1f}/100")
        lines.append(f"**Verdict:** {summary.get('verdict', 'N/A')}")
        lines.append("")

        # Table of contents
        if self.include_toc:
            lines.append("## Table of Contents")
            lines.append("- [Summary](#summary)")
            lines.append("- [Severity Distribution](#severity-distribution)")
            lines.append("- [Findings](#findings)")
            lines.append("- [Agent Results](#agent-results)")
            lines.append("- [Metrics](#metrics)")
            lines.append("")

        # Summary section
        lines.append("## Summary")
        lines.append("")
        lines.append(f"| Metric | Value |")
        lines.append(f"|--------|-------|")
        lines.append(f"| Files Analyzed | {summary.get('files_analyzed', 0)} |")
        lines.append(f"| Total Log Entries | {summary.get('total_entries', 0)} |")
        lines.append(f"| Total Findings | {len(findings)} |")
        lines.append(f"| Score | {summary.get('score', 0):.1f}/100 |")
        lines.append(f"| Duration | {summary.get('duration', 0):.2f}s |")
        lines.append("")

        # Severity distribution
        distribution = summary.get("severity_distribution", {})
        if distribution:
            lines.append("## Severity Distribution")
            lines.append("")
            lines.append("| Severity | Count |")
            lines.append("|----------|-------|")
            for sev, count in sorted(distribution.items(), key=lambda x: x[1], reverse=True):
                if count > 0:
                    lines.append(f"| {sev} | {count} |")
            lines.append("")

        # Findings
        if findings:
            lines.append("## Findings")
            lines.append("")
            for i, finding in enumerate(findings[:50], 1):
                severity = finding.get("severity", "info").upper()
                agent = finding.get("agent", "unknown")
                message = finding.get("message", "")
                lines.append(f"### {i}. [{severity}] {message}")
                lines.append(f"- **Agent:** {agent}")
                if finding.get("file"):
                    lines.append(f"- **File:** `{finding['file']}`")
                if finding.get("line"):
                    lines.append(f"- **Line:** {finding['line']}")
                if finding.get("details"):
                    lines.append(f"- **Details:** {finding['details']}")
                examples = finding.get("examples", [])
                if examples:
                    lines.append(f"- **Examples:**")
                    for ex in examples[:self.max_examples]:
                        lines.append(f"  - `{ex}`")
                lines.append("")

        # Agent results summary
        if agent_results:
            lines.append("## Agent Results")
            lines.append("")
            lines.append("| Agent | Status | Findings | Duration |")
            lines.append("|-------|--------|----------|----------|")
            for agent_name, result in agent_results.items():
                status = result.get("status", "unknown")
                count = result.get("finding_count", 0)
                duration = result.get("duration", 0)
                lines.append(f"| {agent_name} | {status} | {count} | {duration:.2f}s |")
            lines.append("")

        # Metrics
        if metrics:
            lines.append("## Metrics")
            lines.append("")
            lines.append("```json")
            lines.append(json.dumps(metrics, indent=2, default=str))
            lines.append("```")
            lines.append("")

        # Footer
        lines.append("---")
        lines.append("*Generated by LogAnalyzerAI v0.1.0 — Built with: Hermes Agent, MiMo + Claude series*")

        return "\n".join(lines)

    def get_content_type(self) -> str:
        return "text/markdown"

    def get_extension(self) -> str:
        return "md"


class SARIFSerializer(BaseSerializer):
    """Serialize results to SARIF 2.1.0 format for CI/CD integration."""

    SARIF_VERSION = "2.1.0"
    SCHEMA_URI = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json"

    def __init__(self):
        self._severity_map = {
            "critical": "error",
            "high": "error",
            "medium": "warning",
            "low": "note",
            "info": "note",
        }

    def serialize(self, results: dict[str, Any]) -> str:
        findings = results.get("findings", [])

        sarif = {
            "$schema": self.SCHEMA_URI,
            "version": self.SARIF_VERSION,
            "runs": [{
                "tool": {
                    "driver": {
                        "name": "LogAnalyzerAI",
                        "version": "0.1.0",
                        "informationUri": "https://github.com/ayulestari722/LogAnalyzerAI",
                        "rules": self._build_rules(findings),
                    }
                },
                "results": [self._build_result(f, i) for i, f in enumerate(findings)],
                "invocations": [{
                    "executionSuccessful": True,
                    "startTimeUtc": datetime.now(timezone.utc).isoformat(),
                }],
            }],
        }

        return json.dumps(sarif, indent=2, default=str, ensure_ascii=False)

    def _build_rules(self, findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Build SARIF rule definitions from unique finding types."""
        seen_rules: dict[str, dict[str, Any]] = {}
        for finding in findings:
            rule_id = finding.get("rule_id", finding.get("agent", "unknown"))
            if rule_id not in seen_rules:
                seen_rules[rule_id] = {
                    "id": rule_id,
                    "shortDescription": {"text": finding.get("message", "")[:200]},
                    "defaultConfiguration": {
                        "level": self._severity_map.get(
                            finding.get("severity", "info").lower(), "note"
                        )
                    },
                }
        return list(seen_rules.values())

    def _build_result(self, finding: dict[str, Any], index: int) -> dict[str, Any]:
        """Build a single SARIF result entry."""
        result: dict[str, Any] = {
            "ruleId": finding.get("rule_id", finding.get("agent", "unknown")),
            "level": self._severity_map.get(
                finding.get("severity", "info").lower(), "note"
            ),
            "message": {"text": finding.get("message", f"Finding #{index + 1}")},
        }

        if finding.get("file"):
            location = {
                "physicalLocation": {
                    "artifactLocation": {"uri": finding["file"]},
                }
            }
            if finding.get("line"):
                location["physicalLocation"]["region"] = {
                    "startLine": finding["line"]
                }
            result["locations"] = [location]

        return result

    def get_content_type(self) -> str:
        return "application/sarif+json"

    def get_extension(self) -> str:
        return "sarif"


def get_serializer(format_name: str, **kwargs: Any) -> BaseSerializer:
    """Factory function to get appropriate serializer by format name."""
    serializers = {
        "json": JSONSerializer,
        "markdown": MarkdownSerializer,
        "md": MarkdownSerializer,
        "sarif": SARIFSerializer,
    }
    cls = serializers.get(format_name.lower())
    if cls is None:
        raise ValueError(f"Unknown format: {format_name}. Available: {list(serializers.keys())}")
    return cls(**kwargs) if kwargs else cls()
