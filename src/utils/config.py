"""Configuration loading and management."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import yaml


DEFAULT_CONFIG = {
    "orchestrator": {
        "timeout_per_agent": 30.0,
        "max_concurrent_agents": 6,
        "retry_failed_agents": False,
    },
    "agents": {
        "parser": {"enabled": True, "formats": ["json", "syslog", "apache", "nginx"]},
        "anomaly": {"enabled": True, "z_score_threshold": 2.5, "min_samples": 10},
        "pattern": {"enabled": True, "max_patterns": 100, "min_frequency": 3},
        "correlation": {"enabled": True, "time_window_seconds": 60, "min_correlation": 0.7},
        "alert": {"enabled": True, "critical_threshold": 0.9, "high_threshold": 0.7, "medium_threshold": 0.4},
        "metrics": {"enabled": True, "percentiles": [50, 90, 95, 99], "bucket_size_seconds": 60},
        "summary": {"enabled": True, "max_findings": 50, "include_recommendations": True},
    },
    "output": {
        "format": "markdown",
        "include_raw_data": False,
        "max_examples_per_finding": 5,
        "sarif_version": "2.1.0",
    },
    "severity": {
        "weights": {"critical": 10, "high": 7, "medium": 4, "low": 2, "info": 1},
        "score_threshold": 50,
    },
    "logging": {
        "level": "INFO",
        "format": "rich",
        "file": None,
    },
}


def get_default_config() -> dict[str, Any]:
    """Return a deep copy of the default configuration."""
    import copy
    return copy.deepcopy(DEFAULT_CONFIG)


def load_config(config_path: str | Path | None = None) -> dict[str, Any]:
    """Load configuration from YAML file, merged with defaults.

    Args:
        config_path: Path to YAML config file. If None, uses default config.

    Returns:
        Merged configuration dictionary.
    """
    config = get_default_config()

    if config_path is None:
        # Try standard locations
        candidates = [
            Path("config/default.yaml"),
            Path("loganalyzerai.yaml"),
            Path.home() / ".config" / "loganalyzerai" / "config.yaml",
        ]
        for candidate in candidates:
            if candidate.exists():
                config_path = candidate
                break

    if config_path is not None:
        path = Path(config_path)
        if path.exists():
            with open(path, "r", encoding="utf-8") as f:
                user_config = yaml.safe_load(f) or {}
            config = _deep_merge(config, user_config)

    # Environment variable overrides
    env_overrides = {
        "LOGANALYZER_TIMEOUT": ("orchestrator", "timeout_per_agent", float),
        "LOGANALYZER_OUTPUT_FORMAT": ("output", "format", str),
        "LOGANALYZER_LOG_LEVEL": ("logging", "level", str),
    }

    for env_key, (section, key, cast) in env_overrides.items():
        value = os.environ.get(env_key)
        if value is not None:
            config[section][key] = cast(value)

    return config


def _deep_merge(base: dict, override: dict) -> dict:
    """Deep merge two dictionaries, with override taking precedence."""
    result = base.copy()
    for key, value in override.items():
        if key in result and isinstance(result[key], dict) and isinstance(value, dict):
            result[key] = _deep_merge(result[key], value)
        else:
            result[key] = value
    return result


def validate_config(config: dict[str, Any]) -> list[str]:
    """Validate configuration and return list of warnings."""
    warnings = []

    timeout = config.get("orchestrator", {}).get("timeout_per_agent", 0)
    if timeout <= 0:
        warnings.append("orchestrator.timeout_per_agent must be positive")

    z_thresh = config.get("agents", {}).get("anomaly", {}).get("z_score_threshold", 0)
    if z_thresh <= 0:
        warnings.append("agents.anomaly.z_score_threshold must be positive")

    output_format = config.get("output", {}).get("format", "")
    if output_format not in ("json", "markdown", "sarif"):
        warnings.append(f"output.format '{output_format}' not recognized; use json/markdown/sarif")

    return warnings
