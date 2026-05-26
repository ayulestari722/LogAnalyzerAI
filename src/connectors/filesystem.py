"""
FilesystemConnector — Read log files from disk with glob patterns and watch mode.

Provides async file reading capabilities with support for multiple file
patterns, recursive directory scanning, and file watching for new content.
"""

import asyncio
import glob
import os
import time
from pathlib import Path
from typing import Any, AsyncIterator, Dict, List, Optional, Set

try:
    import aiofiles
    HAS_AIOFILES = True
except ImportError:
    HAS_AIOFILES = False


class FilesystemConnector:
    """Connector for reading log files from the filesystem.

    Supports:
    - Single file reading
    - Glob pattern matching for multiple files
    - Recursive directory scanning
    - Watch mode for tailing new content
    - File rotation detection
    """

    def __init__(
        self,
        paths: Optional[List[str]] = None,
        patterns: Optional[List[str]] = None,
        recursive: bool = True,
        encoding: str = "utf-8",
        max_file_size_mb: float = 100.0,
    ) -> None:
        """Initialize the filesystem connector.

        Args:
            paths: List of file or directory paths to read.
            patterns: Glob patterns for file matching (e.g., '*.log').
            recursive: Whether to scan directories recursively.
            encoding: File encoding to use.
            max_file_size_mb: Maximum file size to read in megabytes.
        """
        self.paths = paths or []
        self.patterns = patterns or ["*.log", "*.json", "*.txt"]
        self.recursive = recursive
        self.encoding = encoding
        self.max_file_size_bytes = int(max_file_size_mb * 1024 * 1024)
        self._watched_files: Dict[str, int] = {}  # path -> last position
        self._file_inodes: Dict[str, int] = {}  # path -> inode for rotation detection

    def discover_files(self) -> List[str]:
        """Discover all log files matching the configured paths and patterns.

        Returns:
            List of absolute file paths found.
        """
        discovered: Set[str] = set()

        for path in self.paths:
            abs_path = os.path.abspath(path)

            if os.path.isfile(abs_path):
                if self._is_valid_file(abs_path):
                    discovered.add(abs_path)
            elif os.path.isdir(abs_path):
                for pattern in self.patterns:
                    if self.recursive:
                        glob_pattern = os.path.join(abs_path, "**", pattern)
                        matches = glob.glob(glob_pattern, recursive=True)
                    else:
                        glob_pattern = os.path.join(abs_path, pattern)
                        matches = glob.glob(glob_pattern)

                    for match in matches:
                        if self._is_valid_file(match):
                            discovered.add(os.path.abspath(match))
            else:
                # Treat as glob pattern
                matches = glob.glob(abs_path, recursive=self.recursive)
                for match in matches:
                    if os.path.isfile(match) and self._is_valid_file(match):
                        discovered.add(os.path.abspath(match))

        return sorted(discovered)

    async def read_file(self, file_path: str) -> List[str]:
        """Read all lines from a single file.

        Args:
            file_path: Path to the file to read.

        Returns:
            List of lines from the file.
        """
        abs_path = os.path.abspath(file_path)

        if not os.path.exists(abs_path):
            raise FileNotFoundError(f"File not found: {abs_path}")

        file_size = os.path.getsize(abs_path)
        if file_size > self.max_file_size_bytes:
            raise ValueError(
                f"File too large: {abs_path} ({file_size / 1024 / 1024:.1f}MB > "
                f"{self.max_file_size_bytes / 1024 / 1024:.1f}MB)"
            )

        if HAS_AIOFILES:
            async with aiofiles.open(abs_path, mode="r", encoding=self.encoding, errors="replace") as f:
                content = await f.read()
                return content.splitlines()
        else:
            # Fallback to sync reading in executor
            loop = asyncio.get_event_loop()
            return await loop.run_in_executor(None, self._sync_read_file, abs_path)

    async def read_all_files(self) -> Dict[str, List[str]]:
        """Read all discovered files.

        Returns:
            Dictionary mapping file paths to their lines.
        """
        files = self.discover_files()
        results: Dict[str, List[str]] = {}

        for file_path in files:
            try:
                lines = await self.read_file(file_path)
                results[file_path] = lines
            except (IOError, ValueError) as e:
                results[file_path] = [f"# ERROR reading file: {e}"]

        return results

    async def watch(
        self, interval_seconds: float = 1.0
    ) -> AsyncIterator[Dict[str, List[str]]]:
        """Watch files for new content (tail -f behavior).

        Yields new lines as they appear in watched files.

        Args:
            interval_seconds: How often to check for new content.

        Yields:
            Dictionary mapping file paths to new lines since last check.
        """
        # Initialize positions
        files = self.discover_files()
        for file_path in files:
            if file_path not in self._watched_files:
                try:
                    size = os.path.getsize(file_path)
                    self._watched_files[file_path] = size
                    self._file_inodes[file_path] = os.stat(file_path).st_ino
                except OSError:
                    pass

        while True:
            new_content: Dict[str, List[str]] = {}

            # Re-discover files (handles new files appearing)
            current_files = self.discover_files()

            for file_path in current_files:
                try:
                    new_lines = await self._check_file_changes(file_path)
                    if new_lines:
                        new_content[file_path] = new_lines
                except OSError:
                    continue

            if new_content:
                yield new_content

            await asyncio.sleep(interval_seconds)

    async def _check_file_changes(self, file_path: str) -> List[str]:
        """Check a single file for new content since last read."""
        try:
            current_stat = os.stat(file_path)
            current_inode = current_stat.st_ino
            current_size = current_stat.st_size
        except OSError:
            return []

        # Check for file rotation (inode changed)
        if file_path in self._file_inodes:
            if self._file_inodes[file_path] != current_inode:
                # File was rotated, read from beginning
                self._watched_files[file_path] = 0
                self._file_inodes[file_path] = current_inode

        last_position = self._watched_files.get(file_path, 0)

        # Check for truncation
        if current_size < last_position:
            last_position = 0

        if current_size <= last_position:
            return []

        # Read new content
        new_lines: List[str] = []
        if HAS_AIOFILES:
            async with aiofiles.open(
                file_path, mode="r", encoding=self.encoding, errors="replace"
            ) as f:
                await f.seek(last_position)
                content = await f.read()
                new_lines = content.splitlines()
        else:
            loop = asyncio.get_event_loop()
            new_lines = await loop.run_in_executor(
                None, self._sync_read_from_position, file_path, last_position
            )

        self._watched_files[file_path] = current_size
        return new_lines

    def _sync_read_file(self, file_path: str) -> List[str]:
        """Synchronous file reading fallback."""
        with open(file_path, "r", encoding=self.encoding, errors="replace") as f:
            return f.read().splitlines()

    def _sync_read_from_position(self, file_path: str, position: int) -> List[str]:
        """Synchronous reading from a specific position."""
        with open(file_path, "r", encoding=self.encoding, errors="replace") as f:
            f.seek(position)
            return f.read().splitlines()

    def _is_valid_file(self, file_path: str) -> bool:
        """Check if a file is valid for reading."""
        if not os.path.isfile(file_path):
            return False

        # Skip hidden files
        basename = os.path.basename(file_path)
        if basename.startswith("."):
            return False

        # Skip binary files (check extension)
        binary_extensions = {".gz", ".zip", ".tar", ".bz2", ".xz", ".7z", ".bin", ".exe"}
        _, ext = os.path.splitext(file_path)
        if ext.lower() in binary_extensions:
            return False

        # Check file size
        try:
            size = os.path.getsize(file_path)
            if size > self.max_file_size_bytes:
                return False
            if size == 0:
                return False
        except OSError:
            return False

        return True

    def get_file_info(self, file_path: str) -> Dict[str, Any]:
        """Get metadata about a file."""
        abs_path = os.path.abspath(file_path)
        try:
            stat = os.stat(abs_path)
            return {
                "path": abs_path,
                "size_bytes": stat.st_size,
                "size_human": self._format_size(stat.st_size),
                "modified": time.ctime(stat.st_mtime),
                "created": time.ctime(stat.st_ctime),
                "inode": stat.st_ino,
            }
        except OSError as e:
            return {"path": abs_path, "error": str(e)}

    @staticmethod
    def _format_size(size_bytes: int) -> str:
        """Format file size in human-readable form."""
        for unit in ("B", "KB", "MB", "GB"):
            if size_bytes < 1024:
                return f"{size_bytes:.1f}{unit}"
            size_bytes //= 1024
        return f"{size_bytes:.1f}TB"
