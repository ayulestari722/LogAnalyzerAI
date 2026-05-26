"""
Connector modules for reading log data from various sources.
"""

from src.connectors.filesystem import FilesystemConnector
from src.connectors.log_parser import LogFormatDetector, LogLineParser
from src.connectors.stream import StreamConnector

__all__ = [
    "FilesystemConnector",
    "LogFormatDetector",
    "LogLineParser",
    "StreamConnector",
]
