"""Structured logging setup with rich formatting."""

from __future__ import annotations

import logging
import sys
from typing import Any


_loggers: dict[str, logging.Logger] = {}


class RichFormatter(logging.Formatter):
    """Custom formatter with color-coded severity levels."""

    COLORS = {
        "DEBUG": "\033[36m",     # cyan
        "INFO": "\033[32m",      # green
        "WARNING": "\033[33m",   # yellow
        "ERROR": "\033[31m",     # red
        "CRITICAL": "\033[35m",  # magenta
    }
    RESET = "\033[0m"

    def __init__(self, use_colors: bool = True):
        super().__init__()
        self.use_colors = use_colors

    def format(self, record: logging.LogRecord) -> str:
        timestamp = self.formatTime(record, "%H:%M:%S")
        level = record.levelname
        name = record.name.split(".")[-1] if "." in record.name else record.name

        if self.use_colors and sys.stderr.isatty():
            color = self.COLORS.get(level, "")
            reset = self.RESET
            formatted = f"[{timestamp}] {color}{level:<8}{reset} {name:<20} {record.getMessage()}"
        else:
            formatted = f"[{timestamp}] {level:<8} {name:<20} {record.getMessage()}"

        if record.exc_info and record.exc_info[0] is not None:
            formatted += "\n" + self.formatException(record.exc_info)

        return formatted


def setup_logger(
    name: str = "loganalyzer",
    level: str = "INFO",
    format_style: str = "rich",
    log_file: str | None = None,
) -> logging.Logger:
    """Set up and return a configured logger.

    Args:
        name: Logger name.
        level: Logging level string.
        format_style: 'rich' for colored output, 'plain' for standard.
        log_file: Optional file path for log output.

    Returns:
        Configured logger instance.
    """
    logger = logging.getLogger(name)
    logger.setLevel(getattr(logging, level.upper(), logging.INFO))
    logger.handlers.clear()

    # Console handler
    console_handler = logging.StreamHandler(sys.stderr)
    if format_style == "rich":
        console_handler.setFormatter(RichFormatter(use_colors=True))
    else:
        console_handler.setFormatter(
            logging.Formatter("[%(asctime)s] %(levelname)-8s %(name)-20s %(message)s")
        )
    logger.addHandler(console_handler)

    # File handler (optional)
    if log_file:
        file_handler = logging.FileHandler(log_file, encoding="utf-8")
        file_handler.setFormatter(
            logging.Formatter("[%(asctime)s] %(levelname)-8s %(name)-20s %(message)s")
        )
        logger.addHandler(file_handler)

    _loggers[name] = logger
    return logger


def get_logger(name: str = "loganalyzer") -> logging.Logger:
    """Get an existing logger or create a new one with defaults."""
    if name not in _loggers:
        return setup_logger(name)
    return _loggers[name]
