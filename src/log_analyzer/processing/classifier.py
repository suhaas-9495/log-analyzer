"""Turn individual log events into signals using the configured pattern rules.

Rules are tried in order and the first match wins. ERROR+ lines that match no rule still
become *generic* signals keyed by their message template, so unknown failure modes are
grouped instead of lost. WARN/INFO lines that match nothing are only counted.
"""

from __future__ import annotations

import math
from typing import Any

from log_analyzer.config.schema import AnalyzerConfig, PatternRule
from log_analyzer.correlation.topology import ServiceDirectory
from log_analyzer.models import Category, Level, LogEvent, Severity, Signal, SignalSource
from log_analyzer.processing.templates import template_of

_BUILTIN_GROUP_KEYS = frozenset({"service", "level"})
_MAX_TIMEOUT_SHIFT_S = 600.0  # ignore absurd timeout values when back-dating failures


class PatternClassifier:
    def __init__(self, config: AnalyzerConfig, directory: ServiceDirectory) -> None:
        self._directory = directory
        rules = [r for r in config.patterns if not r.is_condition]
        self._capture_names = {r.name: _capture_names(r) for r in rules}
        # Pre-bucket rules by level so INFO lines (the bulk of traffic) skip most rules.
        self._rules_by_level: dict[Level, tuple[PatternRule, ...]] = {
            level: tuple(r for r in rules if level >= r.min_level) for level in Level
        }
        self._dependency_keywords = config.correlation.dependency_keyword_regex

    def classify(self, event: LogEvent) -> Signal | None:
        lowered: str | None = None
        for rule in self._rules_by_level[event.level]:
            if rule.services and event.service not in rule.services:
                continue
            if rule.prefilter is not None:
                if lowered is None:
                    lowered = event.message.lower()
                if rule.prefilter not in lowered:
                    continue
            captures = self._match(rule, event)
            if captures is not None:
                return self._pattern_signal(rule, event, captures)
        if event.level >= Level.ERROR:
            return self._generic_signal(event)
        return None

    # -------------------------------------------------------------------- matching
    def _match(self, rule: PatternRule, event: LogEvent) -> dict[str, Any] | None:
        captures: dict[str, Any] | None = None
        if rule.regex is not None:
            match = rule.regex.search(event.message)
            if match is not None:
                names = self._capture_names[rule.name]
                captures = {
                    names[i]: value
                    for i, value in enumerate(match.groups())
                    if i < len(names) and value is not None
                }
                captures.update({k: v for k, v in match.groupdict().items() if v is not None})
        elif rule.keyword_regex is not None:
            if rule.keyword_regex.search(event.message):
                captures = {}
        if rule.value_field is not None and "value" not in (captures or {}):
            field_value = event.fields.get(rule.value_field)
            if field_value is not None:
                captures = {**(captures or {}), "value": field_value}
        if captures is None:
            return None
        if rule.threshold is not None or rule.value_range is not None:
            value = _number(captures.get("value"))
            if value is None:
                return None  # garbled number, e.g. "Query took ord_123ms"
            if rule.value_range is not None and not (
                rule.value_range[0] <= value <= rule.value_range[1]
            ):
                return None
            if rule.threshold is not None and value < rule.threshold:
                return None
            captures["value"] = value
        return captures

    # --------------------------------------------------------------------- signals
    def _pattern_signal(
        self, rule: PatternRule, event: LogEvent, captures: dict[str, Any]
    ) -> Signal:
        targets: set[str] = set()
        target = self._directory.resolve(captures.get("target_service"))
        if target:
            targets.add(target)
        if rule.target:
            targets.add(rule.target)
        if not targets and rule.category is Category.DEPENDENCY:
            targets = self._directory.mentions(event.message)
        targets = self._plausible(event.service, targets)
        fingerprint = (
            rule.name,
            *(_group_value(key, event, captures, target) for key in rule.group_by),
        )
        return Signal(
            kind=rule.name,
            source=SignalSource.PATTERN,
            ts=event.ts,
            service=event.service,
            severity=rule.severity,
            category=rule.category,
            fingerprint=fingerprint,
            template=template_of(event.message),
            event=event,
            targets=frozenset(targets),
            effective_ts=_effective_ts(event.ts, captures.get("timeout_ms")),
            attributes={k: v for k, v in captures.items() if k != "target_service"},
            min_occurrences=rule.min_occurrences,
            title=rule.title,
            probable_cause=rule.probable_cause,
            actions=rule.actions,
        )

    def _generic_signal(self, event: LogEvent) -> Signal:
        is_dependency = bool(
            self._dependency_keywords and self._dependency_keywords.search(event.message)
        )
        targets = self._directory.mentions(event.message) if is_dependency else set()
        targets = self._plausible(event.service, targets)
        template = template_of(event.message)
        return Signal(
            kind="error",
            source=SignalSource.GENERIC,
            ts=event.ts,
            service=event.service,
            severity=Severity.HIGH if event.level >= Level.CRITICAL else Severity.MEDIUM,
            category=Category.DEPENDENCY if is_dependency else Category.APPLICATION,
            fingerprint=("error", event.service, template),
            template=template,
            event=event,
            targets=frozenset(targets),
        )


    def _plausible(self, service: str, targets: set[str]) -> set[str]:
        """Keep only dependencies the topology allows (see ServiceDirectory.plausible)."""
        return {t for t in targets if t != service and self._directory.plausible(service, t)}


def _capture_names(rule: PatternRule) -> tuple[str, ...]:
    """Names for *positional* groups: explicit ``captures``, else spec conventions."""
    if rule.captures:
        return rule.captures
    if rule.threshold is not None:
        return ("value",)
    return tuple(k for k in rule.group_by if k not in _BUILTIN_GROUP_KEYS)


def _group_value(key: str, event: LogEvent, captures: dict[str, Any], target: str | None) -> str:
    if key == "service":
        return event.service
    if key == "level":
        return event.level.name
    if key == "target_service" and target:
        return target
    value = captures.get(key)
    return "" if value is None else str(value)


def _effective_ts(ts: float, timeout_ms: Any) -> float | None:
    """A timeout logged at T after D ms means the failure began at T - D."""
    shift = _number(timeout_ms)
    if shift is None or shift <= 0:
        return None
    seconds = shift / 1000.0
    return ts - seconds if seconds <= _MAX_TIMEOUT_SHIFT_S else None


def _number(value: Any) -> float | None:
    if value is None or isinstance(value, bool):
        return None
    try:
        number = float(value)
    except (TypeError, ValueError):
        return None
    return number if math.isfinite(number) else None
