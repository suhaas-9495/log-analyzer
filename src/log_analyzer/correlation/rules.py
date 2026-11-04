"""Evaluate the user's ``alert_rules`` against an incident.

Example (from the problem statement)::

    - name: "API Gateway Cascade"
      condition:
        all:
          - service: "api-gateway"
          - error_rate: ">5%"
          - duration: ">60s"
      severity: HIGH

When a group contains a ``service`` predicate, ``error_rate`` in the same group refers
to *that* service's error rate; otherwise it is the highest rate among the incident's
services. ``pattern`` is a case-insensitive regex over the incident's error templates.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

from log_analyzer.config.schema import AlertRule, ConditionGroup, Predicate
from log_analyzer.correlation.incident import Incident
from log_analyzer.models import Severity

RateLookup = Callable[[str], float]


@dataclass(frozen=True, slots=True)
class RuleContext:
    incident: Incident
    root_cause: str | None
    category: str
    cascade: bool
    severity: Severity
    error_rate: RateLookup


class RuleEngine:
    def __init__(self, rules: tuple[AlertRule, ...]) -> None:
        self._rules = rules

    def matching(self, ctx: RuleContext) -> list[AlertRule]:
        return [rule for rule in self._rules if self._group(rule.condition, ctx)]

    def _group(self, group: ConditionGroup, ctx: RuleContext) -> bool:
        focus = next(
            (p.text for p in group.items if isinstance(p, Predicate) and p.name == "service"),
            None,
        )
        results = (
            self._group(item, ctx)
            if isinstance(item, ConditionGroup)
            else self._predicate(item, ctx, focus)
            for item in group.items
        )
        return all(results) if group.mode == "all" else any(results)

    @staticmethod
    def _predicate(p: Predicate, ctx: RuleContext, focus: str | None) -> bool:
        incident = ctx.incident
        if p.name == "pattern":
            if p.regex is None:
                return False
            return any(p.regex.search(t) for t in incident.templates) or any(
                p.regex.search(kind) for kind in incident.kinds
            )
        if p.name == "service":
            return p.text in incident.services
        if p.name == "root_cause":
            return p.text == ctx.root_cause
        if p.name == "category":
            return p.text == ctx.category
        if p.comparison is None:
            return False
        if p.name == "cascade":
            return p.comparison.test(1.0 if ctx.cascade else 0.0)
        if p.name == "affected_services":
            return p.comparison.test(len(incident.services))
        if p.name == "error_count":
            return p.comparison.test(incident.error_events)
        if p.name == "unique_errors":
            return p.comparison.test(incident.unique_errors)
        if p.name == "duration":
            return p.comparison.test(incident.duration)
        if p.name == "severity":
            return p.comparison.test(float(ctx.severity))
        if p.name == "error_rate":
            services = [focus] if focus else list(incident.services)
            return any(p.comparison.test(ctx.error_rate(s)) for s in services if s)
        raise ValueError(f"unsupported predicate {p.name!r}")  # pragma: no cover
