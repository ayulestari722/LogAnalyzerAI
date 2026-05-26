# LogAnalyzerAI

7-Agent Log Analysis and Anomaly Detection orchestration system powered by AI-driven development workflows. ~5900 LOC, ~129 tests.

## Architecture

| Agent | Role | LOC |
|-------|------|-----|
| ParserAgent | Multi-format log parsing (JSON, syslog, Apache, nginx) | 419 |
| AnomalyAgent | Statistical anomaly detection (z-score spikes, gaps, rate changes) | 285 |
| PatternAgent | Regex pattern matching & frequency analysis | 312 |
| CorrelationAgent | Cross-source event correlation by timestamp & session | 298 |
| AlertAgent | Severity classification & threshold-based alerting | 276 |
| MetricsAgent | Aggregate stats: error rate, latency percentiles, throughput | 264 |
| SummaryAgent | Final report aggregation with recommendations | 248 |

The orchestrator coordinates the 6 analytic agents via `asyncio.gather()` with a per-agent timeout, then runs `SummaryAgent` once their results are in. Severity-weighted scoring rolls findings up to a single verdict.

## Features

- Async parallel agent dispatch with per-agent timeout
- Severity scoring: Critical / High / Medium / Low / Info
- Multiple output formats: JSON, Markdown, SARIF
- Multi-format log parsing (JSON, syslog, nginx access, application logs)
- Statistical anomaly detection with z-score analysis
- Cross-source event correlation and causal chain detection
- Configurable thresholds via YAML
- Rich-formatted CLI output
- Pluggable agent system via `BaseAgent` inheritance
- Watch mode for continuous monitoring

## Usage

```bash
pip install -r requirements.txt
python -m src.cli run ./examples/sample_logs --format markdown
python -m src.cli run ./my_logs --format json --output result.json
python -m src.cli run ./logs --format sarif --output report.sarif
python -m src.cli watch ./logs --interval 5
```

## Token Consumption

During the design and implementation phase, this project consumed **~12M tokens/day** across Hermes Agent, Claude Code, and Xiaomi MiMo V2.5 Pro for multi-agent reasoning, code generation, refactoring loops, and continuous test maintenance.

## Testing

```bash
pytest tests/ -v
```

129 tests covering all 7 agents, orchestrator dispatch, connectors, models, utilities, and CLI integration.

## Project Structure

```
src/
├── agents/          (7 agent modules + base.py)
├── connectors/      (filesystem, log_parser, stream)
├── models/          (log_entry, analysis_state, schemas)
├── utils/           (config, logger, metrics, retry, serializers, severity)
├── orchestrator.py
├── cli.py
└── main.py
tests/               (12 test files, 129 tests)
config/default.yaml
examples/sample_logs/
```

## License

MIT

---

