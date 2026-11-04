"""Extract numeric metrics (latency, utilization) from log events.

Metric rules are configured in ``metrics:``. A value comes from the message via a
regex (named group ``value``, or ``used``/``capacity`` for utilization) or from a
structured field. Garbled values such as ``Request processed in ord_78642ms`` never
match because the regexes require digits, and implausible values are discarded.
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from typing import Any

from log_analyzer.config.schema import MetricKind, MetricRule
from log_analyzer.models import LogEvent

_MAX_LATENCY_MS = 24 * 3600 * 1000.0
_MAX_UTILIZATION = 2.0  # >200% of capacity is a garbled reading, not saturation


@dataclass(frozen=True, slots=True)
class MetricSample:
    metric: str
    kind: MetricKind
    label: str
    value: float  # latency in ms, or utilization ratio (0..1+)
    used: float | None = None
    capacity: float | None = None


class MetricExtractor:
    def __init__(self, rules: tuple[MetricRule, ...]) -> None:
        self._rules = rules
        self._needs_lower = any(rule.prefilter for rule in rules)

    def extract(self, event: LogEvent) -> list[MetricSample]:
        samples: list[MetricSample] = []
        lowered = event.message.lower() if self._needs_lower else ""
        for rule in self._rules:
            if event.level < rule.min_level:
                continue
            sample = (
                self._latency(rule, event, lowered)
                if rule.kind == "latency"
                else self._utilization(rule, event, lowered)
            )
            if sample is not None:
                samples.append(sample)
        return samples

    @staticmethod
    def _latency(rule: MetricRule, event: LogEvent, lowered: str) -> MetricSample | None:
        value: float | None = None
        if rule.regexes and (rule.prefilter is None or rule.prefilter in lowered):
            for regex in rule.regexes:
                match = regex.search(event.message)
                if match is not None:
                    value = _number(match.group("value"))
                    break
        if value is None and event.fields:
            for name in rule.fields:
                value = _number(event.fields.get(name))
                if value is not None:
                    break
        if value is None or value > _MAX_LATENCY_MS:
            return None
        return MetricSample(rule.name, rule.kind, rule.label, value)

    @staticmethod
    def _utilization(rule: MetricRule, event: LogEvent, lowered: str) -> MetricSample | None:
        used: float | None = None
        capacity: float | None = None
        if rule.regexes and (rule.prefilter is None or rule.prefilter in lowered):
            for regex in rule.regexes:
                match = regex.search(event.message)
                if match is not None:
                    used, capacity = _number(match.group("used")), _number(match.group("capacity"))
                    break
        if (used is None or capacity is None) and event.fields and len(rule.fields) == 2:
            used = _number(event.fields.get(rule.fields[0]))
            capacity = _number(event.fields.get(rule.fields[1]))
        if used is None or capacity is None or capacity <= 0:
            return None
        ratio = used / capacity
        if ratio > _MAX_UTILIZATION:
            return None
        return MetricSample(rule.name, rule.kind, rule.label, ratio, used, capacity)


def _number(value: Any) -> float | None:
    """Parse a finite, non-negative number; anything else (``"ord_123"``) is ``None``."""
    if value is None or isinstance(value, bool):
        return None
    try:
        number = float(value)
    except (TypeError, ValueError):
        return None
    if not math.isfinite(number) or number < 0:
        return None
    return number
