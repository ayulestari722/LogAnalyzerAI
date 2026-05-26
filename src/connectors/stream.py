"""Stdin/pipe streaming connector for real-time log ingestion."""

from __future__ import annotations

import asyncio
import sys
from typing import AsyncIterator

from src.models.log_entry import LogEntry
from src.connectors.log_parser import LogLineParser


class StreamConnector:
    """Read log entries from stdin or a pipe in streaming mode.

    Supports both blocking (sync) and non-blocking (async) reads.
    Useful for piping log output directly: `tail -f /var/log/app.log | loganalyzer`
    """

    def __init__(self, buffer_size: int = 1000, flush_interval: float = 1.0):
        self.buffer_size = buffer_size
        self.flush_interval = flush_interval
        self._parser = LogLineParser()
        self._buffer: list[LogEntry] = []
        self._total_lines: int = 0
        self._parse_errors: int = 0

    async def read_stream(self, stream: asyncio.StreamReader | None = None) -> AsyncIterator[list[LogEntry]]:
        """Read from async stream and yield batches of parsed log entries.

        Args:
            stream: Async stream reader. If None, reads from stdin.

        Yields:
            Batches of LogEntry objects.
        """
        if stream is None:
            reader = asyncio.StreamReader()
            protocol = asyncio.StreamReaderProtocol(reader)
            loop = asyncio.get_event_loop()
            await loop.connect_read_pipe(lambda: protocol, sys.stdin)
        else:
            reader = stream

        try:
            while True:
                line_bytes = await asyncio.wait_for(
                    reader.readline(), timeout=self.flush_interval
                )
                if not line_bytes:
                    # EOF reached
                    if self._buffer:
                        yield list(self._buffer)
                        self._buffer.clear()
                    break

                line = line_bytes.decode("utf-8", errors="replace").rstrip("\n\r")
                self._total_lines += 1

                entry = self._parser.parse_line(line, source="stdin")
                if entry:
                    self._buffer.append(entry)
                else:
                    self._parse_errors += 1

                if len(self._buffer) >= self.buffer_size:
                    yield list(self._buffer)
                    self._buffer.clear()

        except asyncio.TimeoutError:
            # Flush on timeout (no new data within interval)
            if self._buffer:
                yield list(self._buffer)
                self._buffer.clear()

    def read_sync(self) -> list[LogEntry]:
        """Synchronous read from stdin until EOF. Returns all entries."""
        entries: list[LogEntry] = []

        for line in sys.stdin:
            line = line.rstrip("\n\r")
            if not line:
                continue
            self._total_lines += 1
            entry = self._parser.parse_line(line, source="stdin")
            if entry:
                entries.append(entry)
            else:
                self._parse_errors += 1

        return entries

    @property
    def stats(self) -> dict[str, int]:
        """Return read statistics."""
        return {
            "total_lines": self._total_lines,
            "parse_errors": self._parse_errors,
            "success_rate": (
                round((self._total_lines - self._parse_errors) / max(self._total_lines, 1) * 100, 1)
            ),
        }
