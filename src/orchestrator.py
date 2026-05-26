"""AsyncOrchestrator — coordinates all agents via asyncio.gather with per-agent timeout."""

from __future__ import annotations

import asyncio
import time
from typing import Any

from src.agents.base import BaseAgent
from src.agents.parser_agent import ParserAgent
from src.agents.anomaly_agent import AnomalyAgent
from src.agents.pattern_agent import PatternAgent
from src.agents.correlation_agent import CorrelationAgent
from src.agents.alert_agent import AlertAgent
from src.agents.metrics_agent import MetricsAgent
from src.agents.summary_agent import SummaryAgent
from src.connectors.filesystem import FilesystemConnector
from src.connectors.log_parser import LogLineParser
from src.models.analysis_state import AnalysisState
from src.models.log_entry import LogEntry, LogBatch
from src.utils.config import load_config
from src.utils.logger import get_logger
from src.utils.metrics import MetricsCollector
from src.utils.severity import SeverityScorer
from src.utils.serializers import get_serializer


logger = get_logger("loganalyzer.orchestrator")


class AsyncOrchestrator:
    """Main orchestrator that coordinates the 7-agent analysis pipeline.

    Dispatches the first 6 agents in parallel via asyncio.gather() with
    per-agent timeouts, then runs SummaryAgent sequentially to aggregate
    all results into a final report.
    """

    def __init__(self, config: dict[str, Any] | None = None):
        self.config = config or load_config()
        self.metrics = MetricsCollector()
        self.scorer = SeverityScorer.from_config(self.config)
        self._agents: list[BaseAgent] = []
        self._summary_agent: SummaryAgent | None = None
        self._initialize_agents()

    def _initialize_agents(self) -> None:
        """Initialize all agents based on configuration."""
        agent_config = self.config.get("agents", {})

        # Parallel agents (dispatched concurrently)
        agent_classes: list[tuple[str, type[BaseAgent]]] = [
            ("parser", ParserAgent),
            ("anomaly", AnomalyAgent),
            ("pattern", PatternAgent),
            ("correlation", CorrelationAgent),
            ("alert", AlertAgent),
            ("metrics", MetricsAgent),
        ]

        for name, cls in agent_classes:
            if agent_config.get(name, {}).get("enabled", True):
                agent = cls(config=agent_config.get(name, {}))
                self._agents.append(agent)
                logger.debug(f"Initialized agent: {agent.name}")

        # Summary agent (runs after all parallel agents complete)
        if agent_config.get("summary", {}).get("enabled", True):
            self._summary_agent = SummaryAgent(config=agent_config.get("summary", {}))
            logger.debug(f"Initialized summary agent: {self._summary_agent.name}")

    async def run_pipeline(
        self,
        target_path: str,
        output_format: str = "markdown",
        output_file: str | None = None,
    ) -> dict[str, Any]:
        """Run the full analysis pipeline on a target path.

        Args:
            target_path: Path to log file or directory containing logs.
            output_format: Output format (json, markdown, sarif).
            output_file: Optional file path to write results.

        Returns:
            Complete analysis results dictionary.
        """
        self.metrics.start_timer("pipeline_total")
        logger.info(f"Starting LogAnalyzerAI pipeline on: {target_path}")

        # Phase 1: Ingest log files
        self.metrics.start_timer("ingestion")
        state = await self._ingest_logs(target_path)
        ingest_duration = self.metrics.stop_timer("ingestion")
        logger.info(
            f"Ingestion complete: {state.total_entries} entries from "
            f"{state.files_analyzed} files ({ingest_duration:.2f}s)"
        )

        if state.total_entries == 0:
            logger.warning("No log entries found. Aborting pipeline.")
            return {"summary": {"verdict": "No data", "score": 0}, "findings": []}

        # Phase 2: Dispatch parallel agents
        self.metrics.start_timer("parallel_agents")
        agent_results = await self._dispatch_parallel_agents(state)
        parallel_duration = self.metrics.stop_timer("parallel_agents")
        logger.info(
            f"Parallel agents complete: {len(agent_results)} agents ran ({parallel_duration:.2f}s)"
        )

        # Collect all findings from parallel agents
        all_findings: list[dict[str, Any]] = []
        # Agent-specific result keys that contain finding-like data
        finding_keys = ["findings", "anomalies", "alerts", "patterns_found",
                        "error_patterns", "correlation_groups", "causal_chains"]
        for agent_name, result in agent_results.items():
            # Try standard "findings" key first
            findings = result.get("findings", [])
            if not findings:
                # Try agent-specific keys
                for key in finding_keys:
                    items = result.get(key, [])
                    if isinstance(items, list) and items:
                        findings = items
                        break
            for finding in findings:
                if isinstance(finding, dict):
                    finding.setdefault("agent", agent_name)
                    finding.setdefault("severity", "info")
                    finding.setdefault("message", finding.get("description", finding.get("pattern", f"Finding from {agent_name}")))
                    all_findings.append(finding)
            self.metrics.increment("total_findings", len(findings))

        state.all_findings = all_findings
        state.agent_results = agent_results

        # Phase 3: Run summary agent
        self.metrics.start_timer("summary_agent")
        summary_result = await self._run_summary_agent(state)
        summary_duration = self.metrics.stop_timer("summary_agent")
        logger.info(f"Summary agent complete ({summary_duration:.2f}s)")

        # Phase 4: Score and finalize
        score = self.scorer.score_findings(all_findings)
        overall_severity = self.scorer.classify_overall(score)
        distribution = self.scorer.get_severity_distribution(all_findings)

        total_duration = self.metrics.stop_timer("pipeline_total")

        results = {
            "summary": {
                "verdict": overall_severity.label,
                "score": round(score, 1),
                "files_analyzed": state.files_analyzed,
                "total_entries": state.total_entries,
                "total_findings": len(all_findings),
                "severity_distribution": distribution,
                "duration": round(total_duration, 2),
                "exceeds_threshold": self.scorer.exceeds_threshold(score),
            },
            "findings": sorted(
                all_findings,
                key=lambda f: f.get("severity_rank", 0),
                reverse=True,
            )[:100],
            "agent_results": {
                name: {
                    "status": r.get("status", "completed"),
                    "finding_count": len(r.get("findings", [])),
                    "duration": r.get("duration", 0),
                }
                for name, r in agent_results.items()
            },
            "metrics": self.metrics.get_summary(),
        }

        # Add summary agent recommendations
        if summary_result:
            results["summary"]["recommendations"] = summary_result.get("recommendations", [])
            results["summary"]["executive_summary"] = summary_result.get("executive_summary", "")

        # Phase 5: Serialize output
        serializer = get_serializer(output_format)
        output_text = serializer.serialize(results)

        if output_file:
            with open(output_file, "w", encoding="utf-8") as f:
                f.write(output_text)
            logger.info(f"Results written to: {output_file}")
        else:
            print(output_text)

        logger.info(
            f"Pipeline complete: {len(all_findings)} findings, "
            f"score {score:.1f}/100, verdict: {overall_severity.label}, "
            f"total time: {total_duration:.2f}s"
        )

        return results

    async def _ingest_logs(self, target_path: str) -> AnalysisState:
        """Ingest log files from the target path."""
        connector = FilesystemConnector(paths=[target_path])
        parser = LogLineParser()

        files = connector.discover_files()
        all_entries: list[LogEntry] = []

        for file_path in files:
            raw_lines = await connector.read_file(file_path)
            for line_num, line in enumerate(raw_lines, 1):
                parsed = parser.parse_line(line, source=file_path)
                if parsed and parsed.get("format") != "empty":
                    # Extract fields from parsed dict
                    fields = parsed.get("fields", {})
                    timestamp = fields.get("timestamp")
                    if isinstance(timestamp, str):
                        try:
                            from datetime import datetime as dt
                            # Normalize: strip timezone to keep all naive
                            ts_clean = timestamp.replace("Z", "").replace("+00:00", "").strip()
                            # Try ISO format first
                            timestamp = dt.fromisoformat(ts_clean)
                        except (ValueError, TypeError):
                            # Try common log format: 22/May/2026:08:01:12 +0000
                            try:
                                from datetime import datetime as dt
                                ts_stripped = timestamp.split(" +")[0].split(" -")[0].strip()
                                timestamp = dt.strptime(ts_stripped, "%d/%b/%Y:%H:%M:%S")
                            except (ValueError, TypeError):
                                timestamp = None
                    elif hasattr(timestamp, 'replace') and timestamp is not None:
                        # Already a datetime, strip tzinfo
                        timestamp = timestamp.replace(tzinfo=None)

                    severity_str = fields.get("level", fields.get("severity", "info"))
                    from src.models.log_entry import Severity as LogSeverity
                    severity = LogSeverity.from_string(str(severity_str))

                    message = fields.get("message", fields.get("request", line.strip()))

                    entry = LogEntry(
                        timestamp=timestamp,
                        severity=severity,
                        message=str(message),
                        source=file_path,
                        line_number=line_num,
                        raw=line,
                        metadata=fields,
                    )
                    all_entries.append(entry)

        state = AnalysisState(
            target_path=target_path,
            files_analyzed=len(files),
            file_paths=files,
        )
        state.log_batch = LogBatch(
            entries=all_entries,
            source=target_path,
            total_lines=len(all_entries),
            parsed_lines=len(all_entries),
        )
        state.log_entries = all_entries
        state.total_entries = len(all_entries)

        return state

    async def _dispatch_parallel_agents(
        self, state: AnalysisState
    ) -> dict[str, dict[str, Any]]:
        """Dispatch all parallel agents concurrently with per-agent timeout."""
        timeout = self.config.get("orchestrator", {}).get("timeout_per_agent", 30.0)
        results: dict[str, dict[str, Any]] = {}

        async def run_agent(agent: BaseAgent) -> tuple[str, dict[str, Any]]:
            self.metrics.start_timer(f"agent_{agent.name}")
            start = time.time()
            try:
                result = await asyncio.wait_for(
                    agent.analyze(state),
                    timeout=timeout,
                )
                duration = time.time() - start
                result["status"] = "completed"
                result["duration"] = round(duration, 3)
            except asyncio.TimeoutError:
                duration = time.time() - start
                result = {
                    "status": "timeout",
                    "duration": round(duration, 3),
                    "findings": [],
                    "error": f"Agent timed out after {timeout}s",
                }
                logger.warning(f"Agent {agent.name} timed out after {timeout}s")
            except Exception as e:
                duration = time.time() - start
                result = {
                    "status": "error",
                    "duration": round(duration, 3),
                    "findings": [],
                    "error": str(e),
                }
                logger.error(f"Agent {agent.name} failed: {e}")
            finally:
                self.metrics.stop_timer(f"agent_{agent.name}")

            return agent.name, result

        # Run all agents concurrently
        tasks = [run_agent(agent) for agent in self._agents]
        completed = await asyncio.gather(*tasks, return_exceptions=False)

        for agent_name, result in completed:
            results[agent_name] = result

        return results

    async def _run_summary_agent(self, state: AnalysisState) -> dict[str, Any] | None:
        """Run the summary agent after all parallel agents complete."""
        if self._summary_agent is None:
            return None

        try:
            result = await self._summary_agent.analyze(state)
            result["status"] = "completed"
            return result
        except Exception as e:
            logger.error(f"Summary agent failed: {e}")
            return {"status": "error", "error": str(e)}

    def __repr__(self) -> str:
        agent_names = [a.name for a in self._agents]
        if self._summary_agent:
            agent_names.append(self._summary_agent.name)
        return (
            f"AsyncOrchestrator(agents={agent_names}, "
            f"timeout={self.config.get('orchestrator', {}).get('timeout_per_agent', 30)}s)"
        )
