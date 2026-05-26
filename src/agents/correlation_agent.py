"""
CorrelationAgent — Cross-source event correlation by timestamp and session.

Identifies related events across different log sources by analyzing
temporal proximity, shared identifiers, and causal relationships.
"""

import re
from collections import defaultdict
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Set, Tuple

from src.agents.base import BaseAgent
from src.models.analysis_state import AnalysisState
from src.models.log_entry import LogEntry, Severity


# Patterns for extracting correlation identifiers
SESSION_ID_PATTERN = re.compile(
    r"(?:session[_-]?id|sid|sess)[=:\s]+([a-zA-Z0-9_-]{8,64})", re.IGNORECASE
)
REQUEST_ID_PATTERN = re.compile(
    r"(?:request[_-]?id|req[_-]?id|trace[_-]?id|correlation[_-]?id|x-request-id)"
    r"[=:\s]+([a-zA-Z0-9_-]{8,64})",
    re.IGNORECASE,
)
USER_ID_PATTERN = re.compile(
    r"(?:user[_-]?id|uid|user)[=:\s]+([a-zA-Z0-9_@.-]{2,64})", re.IGNORECASE
)
TRANSACTION_ID_PATTERN = re.compile(
    r"(?:transaction[_-]?id|tx[_-]?id|txn)[=:\s]+([a-zA-Z0-9_-]{8,64})", re.IGNORECASE
)


class CorrelationAgent(BaseAgent):
    """Agent that correlates events across multiple log sources.

    Correlation strategies:
    - Temporal correlation: events within a time window
    - Session correlation: events sharing session/request IDs
    - Causal correlation: error chains and cascading failures
    - Source correlation: related events from different services
    """

    def __init__(self, config: Optional[Dict[str, Any]] = None) -> None:
        super().__init__(name="correlation", config=config)
        self._time_window_seconds: float = self.config.get("time_window_seconds", 5.0)
        self._max_correlations: int = self.config.get("max_correlations", 100)
        self._min_group_size: int = self.config.get("min_group_size", 2)

    async def analyze(self, state: AnalysisState) -> Dict[str, Any]:
        """Correlate events across log sources.

        Args:
            state: Analysis state with parsed log entries.

        Returns:
            Dictionary with correlation groups, chains, and statistics.
        """
        entries = state.log_entries
        if not entries:
            return {
                "correlation_groups": [],
                "temporal_clusters": [],
                "causal_chains": [],
                "shared_identifiers": {},
                "total_correlated_events": 0,
            }

        # Extract identifiers from all entries
        id_map = self._extract_identifiers(entries)

        # Group by shared identifiers
        id_groups = self._group_by_identifiers(entries, id_map)

        # Temporal clustering
        temporal_clusters = self._find_temporal_clusters(entries)

        # Causal chain detection
        causal_chains = self._detect_causal_chains(entries)

        # Cross-source correlation
        cross_source = self._correlate_across_sources(entries)

        # Merge all correlation results
        all_groups = self._merge_correlation_results(
            id_groups, temporal_clusters, causal_chains, cross_source
        )

        total_correlated = sum(
            len(group.get("entries", [])) for group in all_groups
        )

        state.agent_results["correlation"] = {
            "groups": all_groups,
            "total_correlated": total_correlated,
        }

        return {
            "correlation_groups": all_groups[:self._max_correlations],
            "temporal_clusters": temporal_clusters[:30],
            "causal_chains": causal_chains[:20],
            "shared_identifiers": {
                id_type: len(ids) for id_type, ids in id_map.items()
            },
            "total_correlated_events": total_correlated,
            "cross_source_correlations": len(cross_source),
        }

    def _extract_identifiers(
        self, entries: List[LogEntry]
    ) -> Dict[str, Dict[str, List[int]]]:
        """Extract correlation identifiers from all log entries.

        Returns:
            Nested dict: {id_type: {id_value: [entry_indices]}}
        """
        id_map: Dict[str, Dict[str, List[int]]] = {
            "session_id": defaultdict(list),
            "request_id": defaultdict(list),
            "user_id": defaultdict(list),
            "transaction_id": defaultdict(list),
        }

        patterns = {
            "session_id": SESSION_ID_PATTERN,
            "request_id": REQUEST_ID_PATTERN,
            "user_id": USER_ID_PATTERN,
            "transaction_id": TRANSACTION_ID_PATTERN,
        }

        for idx, entry in enumerate(entries):
            text = entry.message + " " + str(entry.metadata)

            for id_type, pattern in patterns.items():
                matches = pattern.findall(text)
                for match_val in matches:
                    id_map[id_type][match_val].append(idx)

            # Also check metadata for common ID fields
            for key, value in entry.metadata.items():
                key_lower = key.lower()
                if any(k in key_lower for k in ("session", "sid")):
                    id_map["session_id"][str(value)].append(idx)
                elif any(k in key_lower for k in ("request_id", "trace_id", "correlation_id")):
                    id_map["request_id"][str(value)].append(idx)
                elif any(k in key_lower for k in ("user_id", "uid", "user")):
                    id_map["user_id"][str(value)].append(idx)

        return id_map

    def _group_by_identifiers(
        self,
        entries: List[LogEntry],
        id_map: Dict[str, Dict[str, List[int]]],
    ) -> List[Dict[str, Any]]:
        """Group entries that share correlation identifiers."""
        groups: List[Dict[str, Any]] = []

        for id_type, id_values in id_map.items():
            for id_value, indices in id_values.items():
                if len(indices) >= self._min_group_size:
                    group_entries = [entries[i] for i in indices]
                    severities = [e.severity for e in group_entries]
                    max_severity = max(severities, key=lambda s: s.numeric_value)

                    groups.append({
                        "type": "identifier",
                        "identifier_type": id_type,
                        "identifier_value": id_value,
                        "entry_count": len(indices),
                        "entries": [
                            {
                                "line_number": entries[i].line_number,
                                "source": entries[i].source,
                                "message": entries[i].message[:100],
                                "severity": entries[i].severity.value,
                                "timestamp": str(entries[i].timestamp) if entries[i].timestamp else None,
                            }
                            for i in indices[:10]
                        ],
                        "sources": list(set(entries[i].source for i in indices)),
                        "max_severity": max_severity.value,
                        "time_span": self._calculate_time_span(group_entries),
                    })

        groups.sort(key=lambda g: g["entry_count"], reverse=True)
        return groups

    def _find_temporal_clusters(
        self, entries: List[LogEntry]
    ) -> List[Dict[str, Any]]:
        """Find clusters of events that occur within a tight time window."""
        timestamped = [
            (i, e) for i, e in enumerate(entries) if e.timestamp is not None
        ]
        if len(timestamped) < 2:
            return []

        timestamped.sort(key=lambda x: x[1].timestamp)  # type: ignore

        clusters: List[Dict[str, Any]] = []
        current_cluster: List[Tuple[int, LogEntry]] = [timestamped[0]]

        for i in range(1, len(timestamped)):
            idx, entry = timestamped[i]
            prev_idx, prev_entry = current_cluster[-1]

            time_diff = (entry.timestamp - prev_entry.timestamp).total_seconds()  # type: ignore

            if time_diff <= self._time_window_seconds:
                current_cluster.append((idx, entry))
            else:
                if len(current_cluster) >= self._min_group_size:
                    clusters.append(self._build_cluster(current_cluster))
                current_cluster = [(idx, entry)]

        # Don't forget the last cluster
        if len(current_cluster) >= self._min_group_size:
            clusters.append(self._build_cluster(current_cluster))

        # Filter to only interesting clusters (multiple sources or errors)
        interesting_clusters = [
            c for c in clusters
            if len(c.get("sources", [])) > 1
            or c.get("has_errors", False)
            or c["entry_count"] >= 5
        ]

        return interesting_clusters

    def _build_cluster(
        self, cluster_entries: List[Tuple[int, LogEntry]]
    ) -> Dict[str, Any]:
        """Build a cluster summary from a list of entries."""
        entries_only = [e for _, e in cluster_entries]
        sources = list(set(e.source for e in entries_only))
        has_errors = any(
            e.severity in (Severity.ERROR, Severity.CRITICAL) for e in entries_only
        )

        first_ts = entries_only[0].timestamp
        last_ts = entries_only[-1].timestamp
        duration = (last_ts - first_ts).total_seconds() if first_ts and last_ts else 0

        return {
            "type": "temporal_cluster",
            "entry_count": len(cluster_entries),
            "sources": sources,
            "has_errors": has_errors,
            "start_time": str(first_ts) if first_ts else None,
            "end_time": str(last_ts) if last_ts else None,
            "duration_seconds": round(duration, 3),
            "entries": [
                {
                    "line_number": e.line_number,
                    "source": e.source,
                    "message": e.message[:100],
                    "severity": e.severity.value,
                }
                for _, e in cluster_entries[:10]
            ],
        }

    def _detect_causal_chains(
        self, entries: List[LogEntry]
    ) -> List[Dict[str, Any]]:
        """Detect causal chains: sequences of escalating severity events."""
        timestamped = [e for e in entries if e.timestamp is not None]
        if len(timestamped) < 3:
            return []

        timestamped.sort(key=lambda e: e.timestamp)  # type: ignore

        chains: List[Dict[str, Any]] = []
        current_chain: List[LogEntry] = []
        escalation_window = timedelta(seconds=self._time_window_seconds * 6)

        for entry in timestamped:
            if not current_chain:
                if entry.severity.numeric_value >= Severity.WARNING.numeric_value:
                    current_chain = [entry]
                continue

            last_entry = current_chain[-1]
            time_diff = entry.timestamp - last_entry.timestamp  # type: ignore

            if time_diff <= escalation_window:
                if entry.severity.numeric_value >= last_entry.severity.numeric_value:
                    current_chain.append(entry)
                elif entry.severity.numeric_value >= Severity.WARNING.numeric_value:
                    current_chain.append(entry)
                else:
                    if len(current_chain) >= 3:
                        chains.append(self._build_chain(current_chain))
                    current_chain = []
            else:
                if len(current_chain) >= 3:
                    chains.append(self._build_chain(current_chain))
                if entry.severity.numeric_value >= Severity.WARNING.numeric_value:
                    current_chain = [entry]
                else:
                    current_chain = []

        if len(current_chain) >= 3:
            chains.append(self._build_chain(current_chain))

        return chains

    def _build_chain(self, chain_entries: List[LogEntry]) -> Dict[str, Any]:
        """Build a causal chain summary."""
        return {
            "type": "causal_chain",
            "length": len(chain_entries),
            "start_severity": chain_entries[0].severity.value,
            "end_severity": chain_entries[-1].severity.value,
            "escalated": chain_entries[-1].severity.numeric_value > chain_entries[0].severity.numeric_value,
            "start_time": str(chain_entries[0].timestamp),
            "end_time": str(chain_entries[-1].timestamp),
            "entries": [
                {
                    "line_number": e.line_number,
                    "source": e.source,
                    "severity": e.severity.value,
                    "message": e.message[:100],
                }
                for e in chain_entries[:10]
            ],
        }

    def _correlate_across_sources(
        self, entries: List[LogEntry]
    ) -> List[Dict[str, Any]]:
        """Find correlations between events from different sources."""
        sources = set(e.source for e in entries)
        if len(sources) < 2:
            return []

        # Group entries by source
        by_source: Dict[str, List[LogEntry]] = defaultdict(list)
        for entry in entries:
            by_source[entry.source].append(entry)

        correlations: List[Dict[str, Any]] = []
        source_list = list(sources)

        for i in range(len(source_list)):
            for j in range(i + 1, len(source_list)):
                src_a = source_list[i]
                src_b = source_list[j]
                entries_a = by_source[src_a]
                entries_b = by_source[src_b]

                # Find temporally close events between sources
                close_pairs = self._find_close_events(entries_a, entries_b)
                if close_pairs:
                    correlations.append({
                        "type": "cross_source",
                        "source_a": src_a,
                        "source_b": src_b,
                        "correlated_pairs": len(close_pairs),
                        "pairs": close_pairs[:5],
                    })

        return correlations

    def _find_close_events(
        self,
        entries_a: List[LogEntry],
        entries_b: List[LogEntry],
    ) -> List[Dict[str, Any]]:
        """Find events from two sources that are temporally close."""
        ts_a = [(e, e.timestamp) for e in entries_a if e.timestamp]
        ts_b = [(e, e.timestamp) for e in entries_b if e.timestamp]

        if not ts_a or not ts_b:
            return []

        ts_a.sort(key=lambda x: x[1])  # type: ignore
        ts_b.sort(key=lambda x: x[1])  # type: ignore

        pairs: List[Dict[str, Any]] = []
        j_start = 0

        for entry_a, time_a in ts_a:
            for j in range(j_start, len(ts_b)):
                entry_b, time_b = ts_b[j]
                diff = abs((time_a - time_b).total_seconds())  # type: ignore

                if diff <= self._time_window_seconds:
                    # Check if at least one is an error
                    if (entry_a.severity.numeric_value >= Severity.WARNING.numeric_value or
                            entry_b.severity.numeric_value >= Severity.WARNING.numeric_value):
                        pairs.append({
                            "entry_a": {
                                "line": entry_a.line_number,
                                "message": entry_a.message[:80],
                                "severity": entry_a.severity.value,
                            },
                            "entry_b": {
                                "line": entry_b.line_number,
                                "message": entry_b.message[:80],
                                "severity": entry_b.severity.value,
                            },
                            "time_diff_seconds": round(diff, 3),
                        })
                elif time_b > time_a:  # type: ignore
                    break

        return pairs

    def _merge_correlation_results(
        self,
        id_groups: List[Dict[str, Any]],
        temporal_clusters: List[Dict[str, Any]],
        causal_chains: List[Dict[str, Any]],
        cross_source: List[Dict[str, Any]],
    ) -> List[Dict[str, Any]]:
        """Merge all correlation results into a unified list."""
        all_groups: List[Dict[str, Any]] = []
        all_groups.extend(id_groups)
        all_groups.extend(temporal_clusters)
        all_groups.extend(causal_chains)
        all_groups.extend(cross_source)

        # Sort by entry count / significance
        all_groups.sort(
            key=lambda g: g.get("entry_count", g.get("length", g.get("correlated_pairs", 0))),
            reverse=True,
        )

        return all_groups

    @staticmethod
    def _calculate_time_span(entries: List[LogEntry]) -> Optional[float]:
        """Calculate the time span of a group of entries in seconds."""
        timestamps = [e.timestamp for e in entries if e.timestamp is not None]
        if len(timestamps) < 2:
            return None
        timestamps.sort()
        return (timestamps[-1] - timestamps[0]).total_seconds()
