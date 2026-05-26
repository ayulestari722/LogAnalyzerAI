"""Click-based CLI for LogAnalyzerAI."""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path
from typing import Optional

import click

from src.orchestrator import AsyncOrchestrator
from src.utils.config import load_config, validate_config
from src.utils.logger import setup_logger


@click.group()
@click.option("--config", "-c", type=click.Path(exists=True), default=None, help="Path to config YAML file.")
@click.option("--verbose", "-v", is_flag=True, help="Enable verbose (DEBUG) logging.")
@click.option("--quiet", "-q", is_flag=True, help="Suppress all output except results.")
@click.pass_context
def cli(ctx: click.Context, config: Optional[str], verbose: bool, quiet: bool) -> None:
    """LogAnalyzerAI — Multi-agent log analysis and anomaly detection system."""
    ctx.ensure_object(dict)

    # Load configuration
    cfg = load_config(config)
    ctx.obj["config"] = cfg

    # Setup logging
    if quiet:
        log_level = "ERROR"
    elif verbose:
        log_level = "DEBUG"
    else:
        log_level = cfg.get("logging", {}).get("level", "INFO")

    setup_logger("loganalyzer", level=log_level)

    # Validate config
    warnings = validate_config(cfg)
    if warnings and not quiet:
        for w in warnings:
            click.echo(f"⚠ Config warning: {w}", err=True)


@cli.command()
@click.argument("target", type=click.Path(exists=True))
@click.option("--format", "-f", "output_format", type=click.Choice(["json", "markdown", "sarif"]), default=None, help="Output format.")
@click.option("--output", "-o", type=click.Path(), default=None, help="Output file path.")
@click.pass_context
def run(ctx: click.Context, target: str, output_format: Optional[str], output: Optional[str]) -> None:
    """Run analysis on a log file or directory.

    TARGET is a path to a log file or directory containing log files.
    """
    cfg = ctx.obj["config"]
    if output_format:
        cfg["output"]["format"] = output_format
    else:
        output_format = cfg.get("output", {}).get("format", "markdown")

    orchestrator = AsyncOrchestrator(config=cfg)

    try:
        results = asyncio.run(
            orchestrator.run_pipeline(
                target_path=target,
                output_format=output_format,
                output_file=output,
            )
        )
    except KeyboardInterrupt:
        click.echo("\n⚠ Analysis interrupted by user.", err=True)
        sys.exit(130)
    except Exception as e:
        click.echo(f"✗ Analysis failed: {e}", err=True)
        sys.exit(1)

    # Exit code based on threshold
    summary = results.get("summary", {})
    if summary.get("exceeds_threshold", False):
        sys.exit(2)  # Non-zero exit for CI integration


@cli.command()
@click.argument("target", type=click.Path(exists=True))
@click.option("--interval", "-i", type=float, default=5.0, help="Check interval in seconds.")
@click.option("--format", "-f", "output_format", type=click.Choice(["json", "markdown", "sarif"]), default="markdown")
@click.pass_context
def watch(ctx: click.Context, target: str, interval: float, output_format: str) -> None:
    """Watch a log file or directory for changes and re-analyze.

    Continuously monitors TARGET and runs analysis when new entries appear.
    """
    cfg = ctx.obj["config"]
    cfg["output"]["format"] = output_format

    click.echo(f"👁 Watching {target} (interval: {interval}s, Ctrl+C to stop)")

    orchestrator = AsyncOrchestrator(config=cfg)
    last_entry_count = 0

    try:
        while True:
            results = asyncio.run(
                orchestrator.run_pipeline(
                    target_path=target,
                    output_format=output_format,
                )
            )
            current_count = results.get("summary", {}).get("total_entries", 0)

            if current_count != last_entry_count:
                findings = results.get("summary", {}).get("total_findings", 0)
                score = results.get("summary", {}).get("score", 0)
                click.echo(
                    f"[{current_count} entries] {findings} findings, score: {score:.1f}/100",
                    err=True,
                )
                last_entry_count = current_count

            import time
            time.sleep(interval)

    except KeyboardInterrupt:
        click.echo("\n✓ Watch mode stopped.", err=True)


@cli.command()
@click.argument("target", type=click.Path(exists=True))
@click.option("--format", "-f", "output_format", type=click.Choice(["json", "markdown", "sarif"]), default="json")
@click.option("--output", "-o", type=click.Path(), required=True, help="Output file path.")
@click.pass_context
def report(ctx: click.Context, target: str, output_format: str, output: str) -> None:
    """Generate a standalone report file from log analysis.

    Similar to 'run' but always writes to a file and includes extended metadata.
    """
    cfg = ctx.obj["config"]
    cfg["output"]["format"] = output_format
    cfg["output"]["include_raw_data"] = True

    orchestrator = AsyncOrchestrator(config=cfg)

    try:
        results = asyncio.run(
            orchestrator.run_pipeline(
                target_path=target,
                output_format=output_format,
                output_file=output,
            )
        )
        summary = results.get("summary", {})
        click.echo(
            f"✓ Report generated: {output} "
            f"({summary.get('total_findings', 0)} findings, "
            f"score {summary.get('score', 0):.1f}/100)",
            err=True,
        )
    except Exception as e:
        click.echo(f"✗ Report generation failed: {e}", err=True)
        sys.exit(1)


@cli.command()
@click.pass_context
def info(ctx: click.Context) -> None:
    """Show configuration and agent information."""
    cfg = ctx.obj["config"]

    click.echo("LogAnalyzerAI v0.1.0")
    click.echo("=" * 40)
    click.echo(f"\nOrchestrator:")
    click.echo(f"  Timeout per agent: {cfg['orchestrator']['timeout_per_agent']}s")
    click.echo(f"  Max concurrent: {cfg['orchestrator']['max_concurrent_agents']}")
    click.echo(f"\nAgents:")
    for name, agent_cfg in cfg.get("agents", {}).items():
        status = "✓" if agent_cfg.get("enabled", True) else "✗"
        click.echo(f"  {status} {name}")
    click.echo(f"\nOutput:")
    click.echo(f"  Format: {cfg['output']['format']}")
    click.echo(f"  SARIF version: {cfg['output']['sarif_version']}")
    click.echo(f"\nSeverity weights:")
    for level, weight in cfg.get("severity", {}).get("weights", {}).items():
        click.echo(f"  {level}: {weight}")


if __name__ == "__main__":
    cli()
