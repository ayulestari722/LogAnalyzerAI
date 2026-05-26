"""
Base agent abstract class for the LogAnalyzerAI pipeline.

All agents must inherit from BaseAgent and implement the async analyze() method.
"""

from abc import ABC, abstractmethod
from typing import Any, Dict, Optional
import asyncio
import time
import logging

from src.models.analysis_state import AnalysisState


class BaseAgent(ABC):
    """Abstract base class for all analysis agents.

    Provides common infrastructure for timing, logging, configuration,
    and error handling. Subclasses must implement the analyze() method.
    """

    def __init__(self, name: str, config: Optional[Dict[str, Any]] = None) -> None:
        """Initialize the base agent.

        Args:
            name: Human-readable agent name for logging and reporting.
            config: Optional configuration dictionary for agent-specific settings.
        """
        self.name = name
        self.config = config or {}
        self.logger = logging.getLogger(f"loganalyzer.agents.{name}")
        self._start_time: Optional[float] = None
        self._end_time: Optional[float] = None
        self._execution_count: int = 0
        self._total_execution_time: float = 0.0
        self._last_error: Optional[str] = None

    @abstractmethod
    async def analyze(self, state: AnalysisState) -> Dict[str, Any]:
        """Perform analysis on the current pipeline state.

        Args:
            state: The shared analysis state containing log entries and
                   results from other agents.

        Returns:
            Dictionary containing analysis results specific to this agent.
        """
        ...

    async def execute(self, state: AnalysisState) -> Dict[str, Any]:
        """Execute the agent with timing and error handling.

        Wraps the analyze() method with performance tracking and
        structured error handling.

        Args:
            state: The shared analysis state.

        Returns:
            Dictionary with results and metadata.
        """
        self._start_time = time.monotonic()
        self._execution_count += 1
        self.logger.info(f"Agent '{self.name}' starting execution #{self._execution_count}")

        try:
            result = await self.analyze(state)
            self._end_time = time.monotonic()
            elapsed = self._end_time - self._start_time
            self._total_execution_time += elapsed

            self.logger.info(
                f"Agent '{self.name}' completed in {elapsed:.3f}s"
            )

            return {
                "agent": self.name,
                "status": "success",
                "elapsed_seconds": elapsed,
                "execution_number": self._execution_count,
                "results": result,
            }

        except asyncio.CancelledError:
            self._end_time = time.monotonic()
            self._last_error = "cancelled"
            self.logger.warning(f"Agent '{self.name}' was cancelled")
            raise

        except Exception as e:
            self._end_time = time.monotonic()
            elapsed = self._end_time - self._start_time
            self._total_execution_time += elapsed
            self._last_error = str(e)

            self.logger.error(
                f"Agent '{self.name}' failed after {elapsed:.3f}s: {e}"
            )

            return {
                "agent": self.name,
                "status": "error",
                "elapsed_seconds": elapsed,
                "execution_number": self._execution_count,
                "error": str(e),
                "results": {},
            }

    @property
    def average_execution_time(self) -> float:
        """Calculate average execution time across all runs."""
        if self._execution_count == 0:
            return 0.0
        return self._total_execution_time / self._execution_count

    @property
    def is_healthy(self) -> bool:
        """Check if the agent's last execution was successful."""
        return self._last_error is None

    def get_status(self) -> Dict[str, Any]:
        """Get current agent status information."""
        return {
            "name": self.name,
            "execution_count": self._execution_count,
            "total_execution_time": self._total_execution_time,
            "average_execution_time": self.average_execution_time,
            "last_error": self._last_error,
            "is_healthy": self.is_healthy,
        }

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__}(name='{self.name}')>"
