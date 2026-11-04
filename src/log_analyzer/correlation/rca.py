"""Root cause analysis over an incident's dependency graph.

Nodes are the incident's services plus dependencies that were *named* by failing
services but never logged themselves ("virtual" nodes - e.g. a third-party API).
Edges point from a dependent to its dependency and come from two sources:

* **observed**: a signal named its target (``Connection timeout to payment-service``)
* **static**:   ``services[].dependencies`` in the config, between nodes in the incident

Each candidate is scored on three normalised features::

    reach       share of other affected services that (transitively) depend on it
    precedence  how early it started failing (timeout-corrected), earliest = 1
    intrinsic   whether it reports the problem *itself* (pool exhausted, health check
                failing, saturation) rather than blaming someone else

    score = (w_r*reach + w_p*precedence + w_i*intrinsic) / sum(w)
    score *= 0.5 if the candidate itself depends on another failing node (not a sink)

The highest score wins. Confidence is the score, reduced when the runner-up is close
(ambiguous) and capped below certainty: this is heuristic inference from logs.
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass

from log_analyzer.config.schema import RcaWeights
from log_analyzer.correlation.incident import Incident
from log_analyzer.correlation.topology import ServiceDirectory

_MAX_CONFIDENCE = 0.98
_MIN_CONFIDENCE = 0.05
_UNEXPLAINED_CONFIDENCE = 0.25
_VIRTUAL_EVIDENCE = 0.6
_NON_SINK_PENALTY = 0.5
_AMBIGUITY_MARGIN = 0.1
_AMBIGUITY_PENALTY = 0.8


@dataclass(frozen=True, slots=True)
class RootCause:
    service: str
    confidence: float
    inferred: bool  # root never logged: inferred from its dependents' failures
    symptoms: tuple[str, ...]  # other affected services, nearest dependents first
    edges: tuple[tuple[str, str], ...]


class RootCauseAnalyzer:
    def __init__(self, directory: ServiceDirectory, weights: RcaWeights) -> None:
        self._directory = directory
        self._weights = weights

    def analyze(self, incident: Incident) -> RootCause:
        services = list(incident.services)
        nodes = set(services)
        observed = {edge for edge in incident.edges if edge[0] in nodes}
        nodes |= {dst for _, dst in observed}
        edges = observed | self._directory.static_edges(nodes)
        if incident.unexplained:
            root = max(services, key=lambda s: incident.services[s].errors)
            return RootCause(
                service=root,
                confidence=_UNEXPLAINED_CONFIDENCE,
                inferred=False,
                symptoms=tuple(s for s in services if s != root),
                edges=tuple(sorted(edges)),
            )
        if len(nodes) == 1:
            only = services[0]
            evidence = incident.services[only].self_evidence
            return RootCause(only, round(0.6 + 0.3 * evidence, 2), False, (), ())

        dependents = _reverse_reachability(nodes, edges)
        first_seen = self._first_seen(incident, nodes)
        order = sorted(nodes, key=lambda n: (first_seen[n], n))
        rank = {node: i for i, node in enumerate(order)}
        failing = {n for n in nodes if n not in incident.services or incident.services[n].is_failing
                   or incident.services[n].has_detector}
        total_weight = self._weights.reach + self._weights.precedence + self._weights.intrinsic
        scores: dict[str, float] = {}
        for node in nodes:
            others = [s for s in services if s != node]
            reach = (
                len(dependents[node] & set(others)) / len(others) if others else 0.0
            )
            precedence = 1.0 - rank[node] / (len(nodes) - 1)
            impact = incident.services.get(node)
            intrinsic = impact.self_evidence if impact is not None else _VIRTUAL_EVIDENCE
            score = (
                self._weights.reach * reach
                + self._weights.precedence * precedence
                + self._weights.intrinsic * intrinsic
            ) / total_weight
            depends_on_failing = any(src == node and dst in failing for src, dst in edges)
            if depends_on_failing:
                score *= _NON_SINK_PENALTY
            scores[node] = score
        ranked = sorted(scores, key=lambda n: (-scores[n], rank[n]))
        root = ranked[0]
        confidence = scores[root]
        if len(ranked) > 1 and scores[root] - scores[ranked[1]] < _AMBIGUITY_MARGIN:
            confidence *= _AMBIGUITY_PENALTY
        distance = _distances_to(root, nodes, edges)
        symptoms = sorted(
            (s for s in services if s != root),
            key=lambda s: (distance.get(s, len(nodes)), first_seen[s], s),
        )
        return RootCause(
            service=root,
            confidence=round(min(_MAX_CONFIDENCE, max(_MIN_CONFIDENCE, confidence)), 2),
            inferred=root not in incident.services,
            symptoms=tuple(symptoms),
            edges=tuple(sorted(edges)),
        )

    @staticmethod
    def _first_seen(incident: Incident, nodes: set[str]) -> dict[str, float]:
        seen: dict[str, float] = {}
        for node in nodes:
            impact = incident.services.get(node)
            if impact is not None:
                seen[node] = (
                    impact.first_failure_ts if impact.first_failure_ts is not None
                    else impact.first_ts
                )
        for (src, dst), _count in incident.edges.items():
            if dst in nodes and dst not in incident.services:
                src_impact = incident.services.get(src)
                ts = src_impact.first_ts if src_impact else incident.opened_at
                seen[dst] = min(seen.get(dst, ts), ts)
        return seen


def _reverse_reachability(nodes: set[str], edges: set[tuple[str, str]]) -> dict[str, set[str]]:
    """For every node, the set of nodes that (transitively) depend on it."""
    parents: dict[str, set[str]] = {n: set() for n in nodes}
    for src, dst in edges:
        if src in parents and dst in parents:
            parents[dst].add(src)
    result: dict[str, set[str]] = {}
    for node in nodes:
        seen: set[str] = set()
        queue = deque(parents[node])
        while queue:
            current = queue.popleft()
            if current in seen or current == node:
                continue
            seen.add(current)
            queue.extend(parents[current])
        result[node] = seen
    return result


def _distances_to(root: str, nodes: set[str], edges: set[tuple[str, str]]) -> dict[str, int]:
    """Hop distance from each dependent back to ``root`` (BFS on reversed edges)."""
    parents: dict[str, set[str]] = {n: set() for n in nodes}
    for src, dst in edges:
        if src in parents and dst in parents:
            parents[dst].add(src)
    distance = {root: 0}
    queue = deque([root])
    while queue:
        current = queue.popleft()
        for parent in parents[current]:
            if parent not in distance:
                distance[parent] = distance[current] + 1
                queue.append(parent)
    return distance
