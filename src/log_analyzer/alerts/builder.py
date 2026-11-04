"""Build human-actionable alerts from incidents.

The JSON produced by :meth:`AlertView.to_dict` follows the alert format of the problem
statement key-for-key; extra fields are appended after the spec fields.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from log_analyzer.config.schema import AlertRule, AnalyzerConfig
from log_analyzer.correlation.incident import Incident, self_evidence
from log_analyzer.correlation.rca import RootCause
from log_analyzer.models import Category, Severity, Signal, SignalSource
from log_analyzer.timeutil import format_clock, format_duration, format_iso

_ACRONYMS = {"api": "API", "db": "DB", "sql": "SQL", "ui": "UI", "dns": "DNS", "cdn": "CDN"}
_SPLIT = re.compile(r"[-_\s]+")
_SOURCE_RANK = {SignalSource.PATTERN: 2, SignalSource.DETECTOR: 1, SignalSource.GENERIC: 0}
_MESSAGE_PREVIEW = 120


def humanize(name: str) -> str:
    """``api-gateway`` -> ``API Gateway``."""
    return " ".join(_ACRONYMS.get(p.lower(), p.capitalize()) for p in _SPLIT.split(name) if p)


def title_case(text: str) -> str:
    return " ".join(_ACRONYMS.get(w.lower(), w[:1].upper() + w[1:]) for w in text.split())


@dataclass(frozen=True, slots=True)
class Assessment:
    """Everything the correlator decides about an incident at evaluation time."""

    root: RootCause
    cascade: bool
    severity: Severity
    matched_rules: tuple[AlertRule, ...]
    category: str
    title: str


@dataclass(slots=True)
class AlertView:
    alert_id: str
    severity: Severity
    title: str
    summary: str
    category: str
    status: str
    first_ts: float
    last_ts: float
    detected_at: float
    resolved_at: float | None
    affected_services: list[str]
    root_service: str
    symptoms: list[str]
    probable_cause: str
    confidence: float
    evidence: list[str]
    actions: list[str]
    sample_logs: list[str]
    error_count: int
    unique_errors: int
    estimated_failed_requests: int
    total_logs: int
    cascade: bool
    matched_rules: list[str]
    auto_escalate: bool
    severity_history: list[tuple[float, Severity]]
    highlights: list[str] = field(default_factory=list)  # short dashboard bullet lines

    @property
    def logs_grouped(self) -> int:
        return max(0, self.total_logs - self.unique_errors)

    @property
    def noise_reduction(self) -> float:
        return round(100.0 * self.logs_grouped / self.total_logs, 1) if self.total_logs else 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "alert_id": self.alert_id,
            "severity": self.severity.name,
            "title": self.title,
            "summary": self.summary,
            "timeline": {
                "first_occurrence": format_iso(self.first_ts),
                "last_occurrence": format_iso(self.last_ts),
                "total_duration_seconds": round(self.last_ts - self.first_ts),
            },
            "impact": {
                "affected_services": self.affected_services,
                "error_count": self.error_count,
                "unique_errors": self.unique_errors,
                "estimated_failed_requests": self.estimated_failed_requests,
            },
            "root_cause_analysis": {
                "probable_cause": self.probable_cause,
                "confidence": self.confidence,
                "evidence": self.evidence,
            },
            "suggested_actions": [f"{i}. {a}" for i, a in enumerate(self.actions, 1)],
            "sample_logs": self.sample_logs,
            "deduplication_stats": {
                "total_logs_analyzed": self.total_logs,
                "logs_grouped": self.logs_grouped,
                "noise_reduction_percent": self.noise_reduction,
            },
            # ---- extensions beyond the spec format ----
            "status": self.status,
            "category": self.category,
            "root_cause_service": self.root_service,
            "symptom_services": self.symptoms,
            "cascading_failure": self.cascade,
            "matched_rules": self.matched_rules,
            "auto_escalate": self.auto_escalate,
            "detected_at": format_iso(self.detected_at),
            "resolved_at": format_iso(self.resolved_at) if self.resolved_at else None,
            "severity_history": [
                {"at": format_iso(ts), "severity": sev.name} for ts, sev in self.severity_history
            ],
        }


class AlertBuilder:
    def __init__(self, config: AnalyzerConfig) -> None:
        self._config = config
        self._out = config.output
        cascade_rule = config.cascade_rule
        self._cascade_actions = cascade_rule.actions if cascade_rule else ()
        self._cascade_window = (
            cascade_rule.condition_window
            if cascade_rule and cascade_rule.condition_window
            else config.windows.pattern_detection
        )

    # ------------------------------------------------------------------ classification
    def category(self, incident: Incident, root: RootCause, cascade: bool) -> str:
        return self._category(incident, primary_signal(incident, root.service), cascade)

    def describe(
        self,
        incident: Incident,
        root: RootCause,
        cascade: bool,
        matched: tuple[AlertRule, ...],
    ) -> tuple[str, str]:
        """Return ``(category, title)`` for an incident."""
        primary = primary_signal(incident, root.service)
        category = self._category(incident, primary, cascade)
        if matched and not incident.unexplained:
            # A rule names the alert only when it is what set the alert's severity.
            top = max(rule.severity for rule in matched)
            if top >= incident.max_severity and (not cascade or top >= Severity.CRITICAL):
                named = next(r for r in matched if r.severity == top)
                return category, named.title or named.name
        return category, self._title(incident, root, primary, category)

    @staticmethod
    def _category(incident: Incident, primary: Signal | None, cascade: bool) -> str:
        if cascade:
            return "cascade"
        if incident.unexplained or set(incident.kinds) <= {"error_rate_spike", "error"}:
            return "error_rate" if "error_rate_spike" in incident.kinds else "errors"
        if all(s.category is Category.PERFORMANCE for s in incident.first_signals.values()):
            return "performance"
        return primary.category.value if primary else "errors"

    def _title(
        self, incident: Incident, root: RootCause, primary: Signal | None, category: str
    ) -> str:
        n = len(incident.services)
        svc = humanize(root.service)
        if category in ("error_rate", "errors") and incident.unexplained and n > 1:
            return f"Elevated Error Rate Across {n} Services"
        if category == "error_rate":
            return f"Increased Error Rate in {svc}"
        if root.inferred:
            # The root never logged; describe it from its callers' point of view.
            callers = sorted({src for src, dst in incident.edges if dst == root.service})
            caller = callers[0] if callers else root.service
            via = blaming_signal(incident, root.service)
            cause = title_case(via.title) if via and via.title else "Failures"
            who = humanize(caller) if len(callers) == 1 else f"{len(callers)} Services"
            return f"{cause} in {who} - {svc} Unreachable"
        cause = title_case(primary.title) if primary and primary.title else "Errors"
        if category == "cascade":
            lead = cause if svc.lower() in cause.lower() else f"{svc} {cause}"
            return f"{lead} - Cascading Failure Across {n} Services"
        if category == "performance":
            label = str(primary.attributes.get("label", "latency")) if primary else "latency"
            where = "" if root.service.lower() in label.lower() else f" on {svc}"
            spread = f" Affecting {n - 1} Dependent Services" if n > 1 else ""
            return f"Performance Degradation: Rising {title_case(label)}{where}{spread}"
        targets = sorted(t for t in incident.targets if t != root.service)
        towards = f" to {humanize(targets[0])}" if len(targets) == 1 else ""
        spread = f" ({n} Services)" if n > 1 else ""
        return f"{cause} in {svc}{towards}{spread}"

    # ------------------------------------------------------------------------ building
    def build(self, incident: Incident, assessment: Assessment) -> AlertView:
        alert = incident.alert
        if alert is None:
            raise ValueError("incident has not alerted")
        root = assessment.root
        primary = primary_signal(incident, root.service)
        affected = [root.service] if root.inferred else []
        affected += sorted(
            incident.services, key=lambda s: (s != root.service, incident.services[s].first_ts)
        )
        probable = self._probable_cause(root, primary, incident)
        actions = self._actions(incident, root, primary, assessment)
        return AlertView(
            alert_id=alert.alert_id,
            severity=alert.severity,
            title=alert.title,
            summary=self._summary(incident, assessment, primary, probable),
            category=assessment.category,
            status=incident.status.value,
            first_ts=incident.opened_at,
            last_ts=incident.last_activity,
            detected_at=alert.detected_at,
            resolved_at=incident.closed_at,
            affected_services=affected,
            root_service=root.service,
            symptoms=list(root.symptoms),
            probable_cause=probable,
            confidence=root.confidence,
            evidence=self._evidence(incident, assessment, primary)[: self._out.max_evidence],
            actions=actions[: self._out.max_actions],
            sample_logs=self._samples(incident, root.service),
            error_count=incident.error_events,
            unique_errors=incident.unique_errors,
            estimated_failed_requests=len(incident.request_ids) + incident.anonymous_failures,
            total_logs=incident.log_events,
            cascade=assessment.cascade,
            matched_rules=[r.name for r in assessment.matched_rules],
            auto_escalate=any(r.auto_escalate for r in assessment.matched_rules),
            severity_history=list(alert.severity_history),
            highlights=self._highlights(incident, assessment, primary, probable, actions),
        )

    def _probable_cause(self, root: RootCause, primary: Signal | None, incident: Incident) -> str:
        if root.inferred:
            callers = sorted({src for src, dst in incident.edges if dst == root.service})
            return (
                f"{root.service} unavailable (inferred from failing calls by {', '.join(callers)})"
            )
        if incident.unexplained:
            return "No common root cause: heterogeneous errors across unrelated services"
        if primary is None:
            return f"Errors in {root.service}"
        cause = primary.probable_cause or primary.template
        mentions_root = root.service.replace("-", " ").lower() in cause.replace("-", " ").lower()
        return cause if mentions_root else f"{cause} ({root.service})"

    def _summary(
        self, incident: Incident, a: Assessment, primary: Signal | None, probable: str
    ) -> str:
        root = a.root.service
        others = [s for s in a.root.symptoms if s in incident.services]
        if incident.unexplained:
            return (
                f"{len(incident.services)} services show elevated error rates with "
                f"{incident.unique_errors} distinct error signatures and no shared failing "
                "dependency; likely background noise or a broad change (deploy/config)."
            )
        if a.category == "cascade" or (others and a.category != "performance"):
            listed = ", ".join(others[:5]) + (", ..." if len(others) > 5 else "")
            cause = _strip_suffix(probable, f" ({root})")
            return (
                f"{root}: {cause}, causing cascading failures in "
                f"{len(others)} dependent service{'s' if len(others) != 1 else ''}: {listed}."
            )
        if a.category == "performance" and primary is not None:
            attrs = primary.attributes
            text = (
                f"{_subject(root, str(attrs.get('label', 'latency')))} rose to "
                f"{_ms(attrs.get('current_ms'))} ({attrs.get('ratio')}x the "
                f"{_ms(attrs.get('baseline_ms'))} baseline) and is still trending up"
            )
            if others:
                text += f"; dependents also slowing: {', '.join(others)}"
            eta = attrs.get("eta_to_threshold_s")
            if eta:
                text += (
                    f". At this rate it crosses {attrs.get('threshold_ms'):.0f}ms in about "
                    f"{format_duration(float(eta))}"
                )
            return text + "."
        if a.category == "error_rate" and primary is not None:
            attrs = primary.attributes
            top = incident.templates.most_common(1)
            top_text = f"; most common error: '{top[0][0]}'" if top else ""
            return (
                f"Error rate in {root} reached {attrs.get('rate')}% against a "
                f"{attrs.get('baseline')}% baseline{top_text}."
            )
        return (
            f"{incident.log_events} related log events from {root} over "
            f"{format_duration(incident.duration)}: {probable}."
        )

    def _evidence(self, incident: Incident, a: Assessment, primary: Signal | None) -> list[str]:
        root = a.root.service
        lines: list[str] = []
        if incident.unexplained:
            lines.append(
                f"{incident.unique_errors} distinct error signatures across "
                f"{len(incident.services)} services; no failing dependency shared between them"
            )
            for template, count in incident.templates.most_common(3):
                lines.append(f"'{template}' x{count}")
            lines.extend(self._rate_lines(incident, limit=2))
            return lines
        if a.root.inferred:
            lines.append(f"{root} never logged an error itself; it is named by its callers")
        if (
            primary is not None
            and primary.event is not None
            and primary.source is not SignalSource.DETECTOR
        ):
            lines.append(
                f"{root} reported '{_preview(primary.event.message)}' at {format_clock(primary.ts)}"
            )
        sat = incident.latest_detector.get((root, "resource_saturation"))
        if sat is not None:
            attrs = sat.attributes
            if (
                attrs.get("trend_start_pct") is not None
                and attrs["trend_start_pct"] < attrs["utilization_pct"]
            ):
                lines.append(
                    f"{root} {attrs['label']} rose from {attrs['trend_start_pct']:g}% to "
                    f"{attrs['utilization_pct']:g}% between "
                    f"{format_clock(attrs['trend_start_ts'])} and {format_clock(sat.ts)}"
                )
            first_sat = incident.first_signals.get((root, "resource_saturation"))
            if first_sat is not None and first_sat.attributes.get("eta_to_exhaustion_s"):
                lines.append(
                    f"Early warning at {format_clock(first_sat.ts)}: "
                    f"{first_sat.attributes['utilization_pct']:g}% and rising, projected "
                    f"exhaustion in ~{format_duration(first_sat.attributes['eta_to_exhaustion_s'])}"
                )
        latency = [
            s
            for (svc, kind), s in incident.latest_detector.items()
            if kind == "latency_degradation"
        ]
        for sig in sorted(latency, key=lambda s: s.service != root)[:3]:
            attrs = sig.attributes
            lines.append(
                f"{_subject(sig.service, attrs['label'])} {_ms(attrs['current_ms'])} vs "
                f"{_ms(attrs['baseline_ms'])} baseline ({attrs['ratio']:g}x, rising: "
                f"Kendall tau {attrs['trend_tau']:g} over {attrs.get('samples', '?')} samples)"
            )
        callers = _callers(incident, root)
        if callers:
            blamed_at = [s.ts for s in incident.first_signals.values() if root in s.targets]
            window = f" from {format_clock(min(blamed_at))}" if blamed_at else ""
            listed = ", ".join(f"{svc} ({count})" for svc, count in callers[:5])
            lines.append(
                f"{len(callers)} service{'s' if len(callers) != 1 else ''} failed calling "
                f"{root}{window}: {listed}"
            )
        for src, targets, count in _second_level(incident, root)[:2]:
            lines.append(f"{src} failing on {', '.join(targets)} ({count} errors)")
        if a.cascade:
            members = incident.cascade_members
            starts = [
                ts
                for m in members
                if m in incident.services
                and (ts := incident.services[m].first_failure_ts) is not None
            ]
            span = (max(starts) - min(starts)) if starts else 0.0
            lines.append(
                f"{len(members)} services began failing in a chain (each within "
                f"{self._cascade_window:g}s of the previous failure; first-to-last {span:.0f}s)"
            )
        lines.extend(self._rate_lines(incident, limit=2))
        return lines

    @staticmethod
    def _rate_lines(incident: Incident, limit: int) -> list[str]:
        spikes = [
            s for (svc, kind), s in incident.latest_detector.items() if kind == "error_rate_spike"
        ]
        spikes.sort(key=lambda s: -float(s.attributes.get("rate", 0)))
        return [
            f"{s.service} error rate {s.attributes['rate']:g}% "
            f"(baseline {s.attributes['baseline']:g}%)"
            for s in spikes[:limit]
        ]

    def _actions(
        self, incident: Incident, root: RootCause, primary: Signal | None, a: Assessment
    ) -> list[str]:
        if incident.unexplained:
            return [
                "Check for a recent deployment or config change affecting many services",
                "Inspect the top error signatures; fix or silence known-noisy ones",
                "Watch for any one service or dependency standing out (it would page separately)",
            ]
        actions: list[str] = []
        for rule in sorted(a.matched_rules, key=lambda r: -r.severity):
            actions.extend(rule.actions)
        if primary is not None:
            actions.extend(primary.actions)
        for (svc, _kind), sig in sorted(incident.first_signals.items()):
            if svc == root.service and sig is not primary:
                actions.extend(sig.actions)
        if root.inferred:
            via = blaming_signal(incident, root.service)
            if via is not None:
                actions.extend(via.actions)
        if a.cascade:
            actions.extend(self._cascade_actions)
        if not actions:
            actions.append(f"Investigate recent changes and dependencies of {root.service}")
        return list(dict.fromkeys(actions))

    def _samples(self, incident: Incident, root: str) -> list[str]:
        ordered = sorted(incident.samples, key=lambda e: (e.service != root, e.ts))
        limit = self._out.sample_log_max_chars
        return [
            e.raw if len(e.raw) <= limit else e.raw[: limit - 3] + "..."
            for e in ordered[: self._out.max_sample_logs]
        ]

    def _highlights(
        self,
        incident: Incident,
        a: Assessment,
        primary: Signal | None,
        probable: str,
        actions: list[str],
    ) -> list[str]:
        root = a.root.service
        lines: list[str] = []
        symptoms = [s for s in a.root.symptoms if s in incident.services]
        if incident.unexplained:
            spikes = sorted(
                (
                    s
                    for (_svc, kind), s in incident.latest_detector.items()
                    if kind == "error_rate_spike"
                ),
                key=lambda s: -float(s.attributes.get("rate", 0)),
            )
            rates = ", ".join(f"{s.service} {s.attributes['rate']:g}%" for s in spikes[:4])
            if rates:
                lines.append(f"Error Rates: {rates}")
            top = incident.templates.most_common(1)
            if top:
                lines.append(f"Top Pattern: {top[0][0]} (x{top[0][1]})")
            lines.append(
                f"Root Cause: none identified - {incident.unique_errors} distinct errors "
                f"across {len(incident.services)} services, no shared failing dependency"
            )
        elif a.category == "error_rate" and primary is not None:
            attrs = primary.attributes
            lines.append(f"Error Rate: {attrs.get('rate')}% (baseline: {attrs.get('baseline')}%)")
            top = incident.templates.most_common(1)
            if top:
                lines.append(f"Pattern: {top[0][0]}")
        elif a.category == "performance" and primary is not None:
            attrs = primary.attributes
            lines.append(
                f"Latency: {_ms(attrs.get('current_ms'))}, p95 {_ms(attrs.get('p95_ms'))} "
                f"(baseline: {_ms(attrs.get('baseline_ms'))}, {attrs.get('ratio')}x)"
            )
            if attrs.get("eta_to_threshold_s"):
                lines.append(
                    f"Trend: crosses {attrs.get('threshold_ms'):.0f}ms in "
                    f"~{format_duration(float(attrs['eta_to_threshold_s']))} at current rate"
                )
            if symptoms:
                lines.append(f"Services: {root} -> {', '.join(symptoms)}")
        else:
            lines.append(
                f"Services: {root} -> {', '.join(symptoms)}" if symptoms else f"Service: {root}"
            )
            lines.append(f"Root Cause: {probable} ({a.root.confidence:.0%} confidence)")
        if actions:
            lines.append(f"Action: {actions[0]}")
        return lines


# ------------------------------------------------------------------------------ helpers
def primary_signal(incident: Incident, service: str) -> Signal | None:
    """The most telling signal for ``service``: self-reported, severe, from a rule."""
    candidates = [
        incident.latest_detector.get(key, sig)
        for key, sig in incident.first_signals.items()
        if key[0] == service
    ]
    if not candidates:
        return None
    return max(
        candidates,
        key=lambda s: (self_evidence(s), s.severity, _SOURCE_RANK[s.source], -s.ts),
    )


def blaming_signal(incident: Incident, dependency: str) -> Signal | None:
    """The most severe signal in which another service names ``dependency`` as failing."""
    blaming = [s for s in incident.first_signals.values() if dependency in s.targets]
    return max(blaming, key=lambda s: (s.severity, -s.ts)) if blaming else None


def _preview(message: str) -> str:
    text = message.strip()
    return text if len(text) <= _MESSAGE_PREVIEW else text[: _MESSAGE_PREVIEW - 3] + "..."


def _callers(incident: Incident, root: str) -> list[tuple[str, int]]:
    counts: dict[str, int] = {}
    for (src, dst), count in incident.edges.items():
        if dst == root and src != root:
            counts[src] = counts.get(src, 0) + count
    return sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))


def _second_level(incident: Incident, root: str) -> list[tuple[str, list[str], int]]:
    grouped: dict[str, tuple[list[str], int]] = {}
    for (src, dst), count in incident.edges.items():
        if root in (dst, src) or dst not in incident.services:
            continue
        targets, total = grouped.get(src, ([], 0))
        targets.append(dst)
        grouped[src] = (targets, total + count)
    return sorted(((src, sorted(t), c) for src, (t, c) in grouped.items()), key=lambda x: -x[2])


def _subject(service: str, label: str) -> str:
    """``database`` + ``database query time`` -> ``Database query time`` (no repetition)."""
    if service.replace("-", " ").lower() in label.lower():
        return label[:1].upper() + label[1:]
    return f"{service} {label}"


def _ms(value: Any) -> str:
    try:
        return f"{float(value):.0f}ms"
    except (TypeError, ValueError):
        return "?"


def _strip_suffix(text: str, suffix: str) -> str:
    return text[: -len(suffix)] if text.endswith(suffix) else text
