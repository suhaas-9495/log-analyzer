"""Incident: a bounded aggregate of related signals.

An incident never stores every log line. It keeps counters, the first signal of each
(service, kind), the latest detector reading per (service, kind), a handful of sample
lines and a capped set of request ids. Memory per incident is therefore bounded no
matter how many thousands of lines it absorbs.
"""

from __future__ import annotations

import enum
import itertools
from collections import Counter, deque
from dataclasses import dataclass, field

from log_analyzer.config.schema import LimitsConfig
from log_analyzer.models import (
    FAILURE_CATEGORIES,
    Category,
    Level,
    LogEvent,
    Severity,
    Signal,
    SignalSource,
)
from log_analyzer.processing.templates import template_of

_IDS = itertools.count(1)
_SAMPLES_PER_INCIDENT = 24
_RECENT_SIGNAL_TIMES = 64
_FP_TIMES = 16


class IncidentStatus(enum.StrEnum):
    OPEN = "active"
    RESOLVED = "resolved"
    MERGED = "merged"


@dataclass(slots=True)
class ServiceImpact:
    """How one service participates in an incident."""

    name: str
    first_ts: float
    last_ts: float
    first_failure_ts: float | None = None
    log_events: int = 0
    errors: int = 0
    max_severity: Severity = Severity.LOW
    kinds: Counter[str] = field(default_factory=Counter)
    self_evidence: float = 0.0  # 1.0 = the service itself reports the problem
    has_detector: bool = False
    has_performance: bool = False

    @property
    def is_failing(self) -> bool:
        return self.first_failure_ts is not None


@dataclass(slots=True)
class AlertState:
    alert_id: str
    detected_at: float
    severity: Severity
    title: str
    root_cause: str | None
    severity_history: list[tuple[float, Severity]] = field(default_factory=list)


class Incident:
    def __init__(
        self,
        signal: Signal,
        limits: LimitsConfig,
        cascade_window: float,
        *,
        unexplained: bool = False,
    ) -> None:
        self.id = next(_IDS)
        self.limits = limits
        self.cascade_window = cascade_window
        self.unexplained = unexplained
        self.status = IncidentStatus.OPEN
        self.opened_at = signal.ts
        self.last_activity = signal.ts
        self.last_failure_ts: float | None = None
        self.closed_at: float | None = None
        self.services: dict[str, ServiceImpact] = {}
        self.edges: Counter[tuple[str, str]] = Counter()
        self.targets: set[str] = set()
        self.fingerprints: set[tuple[str, ...]] = set()
        self.templates: Counter[str] = Counter()
        self.template_overflow = 0
        self.kinds: Counter[str] = Counter()
        self.first_signals: dict[tuple[str, str], Signal] = {}
        self.latest_detector: dict[tuple[str, str], Signal] = {}
        self.samples: list[LogEvent] = []
        self._sample_keys: set[tuple[str, str]] = set()
        self.request_ids: set[str] = set()
        self.anonymous_failures = 0
        self.log_events = 0
        self.error_events = 0
        self.context_events = 0
        self.signal_count = 0
        self.recent_signal_ts: deque[float] = deque(maxlen=_RECENT_SIGNAL_TIMES)
        self.fingerprint_ts: dict[tuple[str, ...], deque[float]] = {}
        self.max_severity = Severity.LOW
        self.min_occurrences_override: int | None = None
        self.cascade_members: list[str] = []
        self.alert: AlertState | None = None
        self.structure_version = 0  # bumps when services/edges/kinds change
        self.evaluated_version = -1
        self.evaluated_at = -1.0
        self.inhibited_by: Incident | None = None
        self.add(signal)

    # ------------------------------------------------------------------ properties
    @property
    def confirmed(self) -> bool:
        """Corroborated enough that static dependencies may be used to link to it."""
        return self.alert is not None or any(s.has_detector for s in self.services.values())

    @property
    def duration(self) -> float:
        return max(0.0, self.last_activity - self.opened_at)

    @property
    def unique_errors(self) -> int:
        return len(self.templates) + self.template_overflow

    def burst(self, count: int) -> float:
        """Seconds spanned by the last ``count`` log-backed signals (inf if fewer)."""
        return _span(self.recent_signal_ts, count)

    def fingerprint_burst(self, count: int) -> float:
        """Smallest span covering ``count`` repeats of any single fingerprint."""
        return min(
            (_span(times, count) for times in self.fingerprint_ts.values()), default=float("inf")
        )

    # ---------------------------------------------------------------------- adding
    def add(self, signal: Signal) -> None:
        self.signal_count += 1
        self.opened_at = min(self.opened_at, signal.ts)
        self.last_activity = max(self.last_activity, signal.ts)
        self.kinds[signal.kind] += 1
        self.max_severity = max(self.max_severity, signal.severity)
        if signal.min_occurrences is not None:
            current = self.min_occurrences_override
            self.min_occurrences_override = (
                signal.min_occurrences if current is None else min(current, signal.min_occurrences)
            )
        if len(self.fingerprints) < self.limits.max_fingerprints:
            self.fingerprints.add(signal.fingerprint)
        impact = self._impact(signal)
        self._track_failure(signal, impact)
        new_edges = False
        for target in signal.targets:
            if target not in self.targets:
                self.targets.add(target)
                new_edges = True
            self.edges[(signal.service, target)] += 1
        if new_edges:
            self.structure_version += 1
        key = (signal.service, signal.kind)
        if key not in self.first_signals:
            self.first_signals[key] = signal
            self.structure_version += 1
        if signal.source is SignalSource.DETECTOR:
            self.latest_detector[key] = signal
        if signal.event is not None and signal.source is not SignalSource.DETECTOR:
            self.recent_signal_ts.append(signal.ts)
            times = self.fingerprint_ts.get(signal.fingerprint)
            if times is None and len(self.fingerprint_ts) < self.limits.max_fingerprints:
                times = self.fingerprint_ts[signal.fingerprint] = deque(maxlen=_FP_TIMES)
            if times is not None:
                times.append(signal.ts)
            self._add_log(signal.service, signal.template, signal.event)

    def add_context(self, event: LogEvent) -> None:
        """Count a related WARN+ line that did not itself produce a signal."""
        if event.service not in self.services:
            return
        self.context_events += 1
        self.last_activity = max(self.last_activity, event.ts)
        self.services[event.service].last_ts = max(self.services[event.service].last_ts, event.ts)
        self._add_log(event.service, template_of(event.message), event)

    def _impact(self, signal: Signal) -> ServiceImpact:
        impact = self.services.get(signal.service)
        if impact is None:
            impact = ServiceImpact(signal.service, signal.ts, signal.ts)
            self.services[signal.service] = impact
            self.structure_version += 1
        impact.first_ts = min(impact.first_ts, signal.ts)
        impact.last_ts = max(impact.last_ts, signal.ts)
        impact.kinds[signal.kind] += 1
        impact.max_severity = max(impact.max_severity, signal.severity)
        impact.self_evidence = max(impact.self_evidence, self_evidence(signal))
        if signal.source is SignalSource.DETECTOR:
            impact.has_detector = True
        if signal.category is Category.PERFORMANCE:
            impact.has_performance = True
        return impact

    def _track_failure(self, signal: Signal, impact: ServiceImpact) -> None:
        if not signal.is_failure:
            return
        if impact.first_failure_ts is None:
            # Cascade membership: the first failing service is the origin; a newly failing
            # service joins the cascade if its failure began (timeout-corrected) within the
            # cascade window of the incident's most recent failure.
            impact.first_failure_ts = signal.start_ts
            if (
                self.last_failure_ts is None
                or signal.start_ts - self.last_failure_ts <= self.cascade_window
            ):
                self.cascade_members.append(signal.service)
            self.structure_version += 1
        else:
            impact.first_failure_ts = min(impact.first_failure_ts, signal.start_ts)
        self.last_failure_ts = max(self.last_failure_ts or signal.ts, signal.ts)

    def _add_log(self, service: str, template: str, event: LogEvent) -> None:
        self.log_events += 1
        impact = self.services[service]
        impact.log_events += 1
        if event.level >= Level.ERROR:
            self.error_events += 1
            impact.errors += 1
            if event.request_id:
                if len(self.request_ids) < self.limits.max_request_ids:
                    self.request_ids.add(event.request_id)
                else:
                    self.anonymous_failures += 1
            else:
                self.anonymous_failures += 1
        if template in self.templates or len(self.templates) < self.limits.max_fingerprints:
            self.templates[template] += 1
        else:
            self.template_overflow += 1
        sample_key = (service, template)
        if sample_key not in self._sample_keys and len(self.samples) < _SAMPLES_PER_INCIDENT:
            self._sample_keys.add(sample_key)
            self.samples.append(event)

    # --------------------------------------------------------------------- merging
    def absorb(self, other: Incident, *, keep_unexplained: bool = False) -> None:
        """Merge ``other`` into this incident (used when a signal bridges two incidents)."""
        self.opened_at = min(self.opened_at, other.opened_at)
        self.last_activity = max(self.last_activity, other.last_activity)
        if other.last_failure_ts is not None:
            self.last_failure_ts = max(
                self.last_failure_ts or other.last_failure_ts, other.last_failure_ts
            )
        for name, theirs in other.services.items():
            mine = self.services.get(name)
            if mine is None:
                self.services[name] = theirs
                continue
            mine.first_ts = min(mine.first_ts, theirs.first_ts)
            mine.last_ts = max(mine.last_ts, theirs.last_ts)
            if theirs.first_failure_ts is not None:
                mine.first_failure_ts = min(
                    mine.first_failure_ts or theirs.first_failure_ts, theirs.first_failure_ts
                )
            mine.log_events += theirs.log_events
            mine.errors += theirs.errors
            mine.max_severity = max(mine.max_severity, theirs.max_severity)
            mine.kinds.update(theirs.kinds)
            mine.self_evidence = max(mine.self_evidence, theirs.self_evidence)
            mine.has_detector = mine.has_detector or theirs.has_detector
            mine.has_performance = mine.has_performance or theirs.has_performance
        self.edges.update(other.edges)
        self.targets |= other.targets
        room = self.limits.max_fingerprints - len(self.fingerprints)
        self.fingerprints |= set(itertools.islice(other.fingerprints, max(0, room)))
        self.templates.update(other.templates)
        self.template_overflow += other.template_overflow
        self.kinds.update(other.kinds)
        for key, signal in other.first_signals.items():
            if key not in self.first_signals or signal.ts < self.first_signals[key].ts:
                self.first_signals[key] = signal
        for key, signal in other.latest_detector.items():
            if key not in self.latest_detector or signal.ts > self.latest_detector[key].ts:
                self.latest_detector[key] = signal
        for event in other.samples:
            if len(self.samples) >= _SAMPLES_PER_INCIDENT:
                break
            self.samples.append(event)
        room_ids = self.limits.max_request_ids - len(self.request_ids)
        self.request_ids |= set(itertools.islice(other.request_ids, max(0, room_ids)))
        self.anonymous_failures += other.anonymous_failures
        self.log_events += other.log_events
        self.error_events += other.error_events
        self.context_events += other.context_events
        for fingerprint, times in other.fingerprint_ts.items():
            mine_ts = self.fingerprint_ts.get(fingerprint)
            if mine_ts is None:
                if len(self.fingerprint_ts) < self.limits.max_fingerprints:
                    self.fingerprint_ts[fingerprint] = times
            else:
                combined = sorted((*mine_ts, *times))
                mine_ts.clear()
                mine_ts.extend(combined[-_FP_TIMES:])
        merged_ts = sorted((*self.recent_signal_ts, *other.recent_signal_ts))
        self.recent_signal_ts.clear()
        self.recent_signal_ts.extend(merged_ts[-_RECENT_SIGNAL_TIMES:])
        self.signal_count += other.signal_count
        self.max_severity = max(self.max_severity, other.max_severity)
        if other.min_occurrences_override is not None:
            self.min_occurrences_override = min(
                self.min_occurrences_override or other.min_occurrences_override,
                other.min_occurrences_override,
            )
        for member in other.cascade_members:
            if member not in self.cascade_members:
                self.cascade_members.append(member)
        self.unexplained = self.unexplained and (keep_unexplained or other.unexplained)
        self.structure_version += 1
        other.status = IncidentStatus.MERGED


def self_evidence(signal: Signal) -> float:
    """How strongly a signal says "the problem is *in* this service" (0..1).

    * resource/availability problems reported without naming another service
      ("Connection pool exhausted" from the database itself, health checks failing,
      saturation detected on the service's own gauge) -> 1.0
    * performance degradation of the service itself -> 0.7 (may be inherited)
    * application errors -> 0.3
    * failures that name another service as the culprit -> 0.1 (a symptom)
    """
    if signal.targets:
        return 0.1
    if signal.kind == "error_rate_spike":
        return 0.4  # says the service is erroring, not why
    if signal.category in FAILURE_CATEGORIES - {Category.DEPENDENCY}:
        return 1.0
    if signal.category is Category.PERFORMANCE:
        return 0.7
    if signal.category is Category.DEPENDENCY:
        return 0.2
    return 0.3


def _span(times: deque[float], count: int) -> float:
    if not times:
        return float("inf")
    if count <= 1:
        return 0.0
    if len(times) < count:
        return float("inf")
    return times[-1] - times[-count]
