"""Group signals into incidents and decide when an incident becomes an alert.

Linking rules (a signal joins every open incident it links to; several matches merge):

1. **Same fingerprint** - de-duplication of repeats of the same problem.
2. **Explicit evidence** - the signal names a dependency that is in the incident
   (``Connection timeout to order-service``), or the incident already names the
   signal's service as a failing dependency.
3. **Performance propagation** - a latency-degradation signal joins an incident in
   which a service it depends on (or that depends on it, per ``services[].dependencies``)
   is also degrading. Slowness propagates up a call chain without any log naming it.
4. **Same service** - *weak* signals (unclassified errors, error-rate spikes) are
   absorbed by an open incident that already contains their service; stronger
   signals are absorbed only by a *confirmed* incident (alerting or detector-backed).

Neither time proximity nor a static dependency edge on its own links two *failures*.
That is deliberate: the sample data has long bands of random errors across ten
services, and the API gateway depends on all of them. Linking on timing or on the
static graph turns that background noise into a fake CRITICAL "cascade". Failures
link only when a log line provides evidence.

Error-rate spikes not explained by any incident are gathered into a single
"unexplained" incident so that broad, unrelated noise produces one alert, not one per
service. While that noise alert is active, *weak* incidents on the same services (see
:meth:`Correlator._strong`) are folded into it instead of paging separately - the same
idea as inhibition rules in Prometheus Alertmanager.

Incidents close after ``alert_grouping`` seconds without activity (the noise bucket after
``error_rate_baseline``). Detector conditions that recur within ``alert_cooldown``
re-open their previous alert instead of paging again.
"""

from __future__ import annotations

from collections import OrderedDict
from collections.abc import Callable
from dataclasses import dataclass
from enum import StrEnum

from log_analyzer.alerts.builder import AlertBuilder, Assessment
from log_analyzer.config.schema import AnalyzerConfig
from log_analyzer.correlation.incident import AlertState, Incident, IncidentStatus
from log_analyzer.correlation.rca import RootCauseAnalyzer
from log_analyzer.correlation.rules import RuleContext, RuleEngine
from log_analyzer.correlation.topology import ServiceDirectory
from log_analyzer.models import Category, LogEvent, Severity, Signal, SignalSource
from log_analyzer.timeutil import format_date_compact

_CORRELATABLE = frozenset(
    {Category.DEPENDENCY, Category.RESOURCE, Category.AVAILABILITY, Category.PERFORMANCE}
)
_UNEXPLAINED_KEY = ("error_rate_spike", "*")


class AlertEventKind(StrEnum):
    NEW = "NEW"
    UPDATED = "UPDATED"
    RESOLVED = "RESOLVED"
    REOPENED = "REOPENED"
    MERGED = "MERGED"  # re-classified into another alert (e.g. background noise)


@dataclass(frozen=True, slots=True)
class AlertEvent:
    kind: AlertEventKind
    ts: float
    incident: Incident
    assessment: Assessment


RateLookup = Callable[[str, float], float]


@dataclass(slots=True)
class CorrelatorStats:
    incidents_opened: int = 0
    incidents_merged: int = 0
    incidents_suppressed: int = 0  # closed without ever meeting the alerting bar
    incidents_inhibited: int = 0  # folded into an active "no common cause" alert
    suppressed_logs: int = 0
    reopened: int = 0
    alerts_evicted: int = 0


class Correlator:
    def __init__(
        self,
        config: AnalyzerConfig,
        directory: ServiceDirectory,
        error_rate: RateLookup | None = None,
    ) -> None:
        self._config = config
        self._directory = directory
        self._error_rate = error_rate or (lambda _service, _now: 0.0)
        self._rca = RootCauseAnalyzer(directory, config.correlation.rca_weights)
        self._rules = RuleEngine(config.alert_rules)
        self._builder = AlertBuilder(config)
        cascade_rule = config.cascade_rule
        self._cascade_severity = cascade_rule.severity if cascade_rule else None
        self._cascade_window = (
            cascade_rule.condition_window
            if cascade_rule and cascade_rule.condition_window
            else config.windows.pattern_detection
        )
        self._grouping = config.windows.alert_grouping
        # Background noise is a *condition*, not a burst: keep its bucket open for a full
        # baseline window of quiet so intermittent spikes do not make the alert flap.
        self._noise_idle = max(config.windows.alert_grouping, config.windows.noise_hold)
        self._cooldown = config.windows.alert_cooldown
        self._reevaluate_after = config.windows.alert_grouping / 2
        self._open: list[Incident] = []
        self._by_fingerprint: dict[tuple[str, ...], Incident] = {}
        self._cooldown_index: OrderedDict[tuple[str, ...], Incident] = OrderedDict()
        self._alerted: OrderedDict[int, Incident] = OrderedDict()
        self._assessments: dict[int, Assessment] = {}
        self._sequence: dict[str, int] = {}
        self.stats = CorrelatorStats()

    # --------------------------------------------------------------------------- API
    @property
    def builder(self) -> AlertBuilder:
        return self._builder

    def ingest(self, signal: Signal) -> list[AlertEvent]:
        events = self.advance(signal.ts)
        linked = self._candidates(signal)
        reopened = False
        if linked:
            incident = max(linked, key=lambda inc: (inc.alert is not None, inc.signal_count))
            for other in linked:
                if other is not incident:
                    self._merge(incident, other)
            incident.add(signal)
        else:
            reopened_incident = self._reopen(signal)
            reopened = reopened_incident is not None
            incident = reopened_incident or self._create(signal)
        self._by_fingerprint[signal.fingerprint] = incident
        events.extend(self._evaluate(incident, signal.ts, reopened=reopened))
        return events

    def advance(self, now: float) -> list[AlertEvent]:
        """Close incidents idle for longer than the grouping window."""
        events: list[AlertEvent] = []
        still_open: list[Incident] = []
        for incident in self._open:
            idle_limit = self._noise_idle if incident.unexplained else self._grouping
            if now - incident.last_activity > idle_limit:
                events.extend(self._close(incident, incident.last_activity + idle_limit))
            else:
                still_open.append(incident)
        self._open = still_open
        return events

    def alerts(self) -> list[tuple[Incident, Assessment]]:
        """Every incident that alerted (active and resolved), freshly assessed."""
        result: list[tuple[Incident, Assessment]] = []
        for incident in self._alerted.values():
            if incident.status is IncidentStatus.MERGED:
                continue
            assessment = self._assess(incident)
            self._assessments[incident.id] = assessment
            result.append((incident, assessment))
        return result

    def open_incidents(self) -> list[Incident]:
        return list(self._open)

    # --------------------------------------------------------------------- linking
    def _candidates(self, signal: Signal) -> list[Incident]:
        linked = [inc for inc in self._open if not inc.unexplained and self._linked(inc, signal)]
        by_fp = self._by_fingerprint.get(signal.fingerprint)
        if by_fp is not None and by_fp.status is IncidentStatus.OPEN:
            if not by_fp.unexplained:
                if by_fp not in linked:
                    linked.insert(0, by_fp)
            elif not linked:
                return [by_fp]  # a repeat of something already filed as noise
        # Evidence-linked incidents always win over the noise bucket, and the two kinds
        # are never merged with each other.
        if linked:
            return linked
        home = self._same_service_home(signal)
        return [home] if home is not None else []

    def _linked(self, incident: Incident, signal: Signal) -> bool:
        services = incident.services
        if signal.targets & services.keys():
            return True
        if signal.category in _CORRELATABLE and signal.service in incident.targets:
            return True
        if signal.kind == "latency_degradation":
            return any(
                impact.has_performance and self._directory.linked(signal.service, name)
                for name, impact in services.items()
                if name != signal.service
            )
        return False

    def _same_service_home(self, signal: Signal) -> Incident | None:
        spike = signal.kind == "error_rate_spike"
        homes = [
            inc
            for inc in self._open
            if signal.service in inc.services
            and not inc.unexplained
            and (signal.is_weak or signal.category in _CORRELATABLE)
            and (
                # A spike is "explained" by an incident that is already alerting on the
                # service or is strong; other correlatable signals need a confirmed
                # incident; plain weak errors join any incident of their service.
                (inc.alert is not None or self._strong(inc, self._assessments.get(inc.id)))
                if spike
                else (inc.confirmed or signal.is_weak)
            )
        ]
        if not homes and spike:
            # A spike no known incident explains joins the shared "unexplained" bucket.
            homes = [inc for inc in self._open if inc.unexplained]
        if not homes:
            return None
        return max(homes, key=lambda inc: (not inc.unexplained, inc.last_activity))

    def attach_context(self, event: LogEvent) -> None:
        """Attach a WARN+ line that produced no signal to the incident of its service.

        Such lines (e.g. ``WARN Request processed in 431ms`` during a slowdown) are part
        of the evidence an engineer would look at, and are counted in the alert's
        de-duplication statistics and sample logs.
        """
        homes = [inc for inc in self._open if event.service in inc.services]
        if homes:
            max(homes, key=lambda inc: (not inc.unexplained, inc.last_activity)).add_context(event)

    # ------------------------------------------------------------------- lifecycle
    def _create(self, signal: Signal) -> Incident:
        unexplained = signal.kind == "error_rate_spike"
        incident = Incident(
            signal, self._config.limits, self._cascade_window, unexplained=unexplained
        )
        self.stats.incidents_opened += 1
        self._register(incident)
        if len(self._open) > self._config.limits.max_open_incidents:
            oldest = min(self._open, key=lambda inc: inc.last_activity)
            self._open.remove(oldest)
            self._close(oldest, signal.ts)
        return incident

    def _reopen(self, signal: Signal) -> Incident | None:
        """Re-open a recently resolved alert for a recurring *detector* condition."""
        if signal.source is not SignalSource.DETECTOR:
            return None
        key = _UNEXPLAINED_KEY if signal.kind == "error_rate_spike" else signal.fingerprint
        incident = self._cooldown_index.get(key)
        if incident is None or incident.status is not IncidentStatus.RESOLVED:
            return None
        if signal.ts - incident.last_activity > self._cooldown:
            return None
        incident.status = IncidentStatus.OPEN
        incident.closed_at = None
        incident.add(signal)
        self._register(incident)
        self.stats.reopened += 1
        return incident

    def _register(self, incident: Incident) -> None:
        if incident not in self._open:
            self._open.append(incident)
        for fingerprint in incident.fingerprints:
            self._by_fingerprint[fingerprint] = incident

    def _merge(self, primary: Incident, other: Incident) -> None:
        primary.absorb(other)
        self.stats.incidents_merged += 1
        if other in self._open:
            self._open.remove(other)
        for fingerprint in other.fingerprints:
            self._by_fingerprint[fingerprint] = primary
        if other.alert is not None:
            if primary.alert is None:
                primary.alert = other.alert
            self._alerted.pop(other.id, None)
            self._alerted.setdefault(primary.id, primary)

    def _close(self, incident: Incident, at: float) -> list[AlertEvent]:
        incident.status = IncidentStatus.RESOLVED
        incident.closed_at = at
        for fingerprint in incident.fingerprints:
            if self._by_fingerprint.get(fingerprint) is incident:
                del self._by_fingerprint[fingerprint]
        if incident.alert is None:
            inhibitor = incident.inhibited_by
            if inhibitor is not None and inhibitor.status is not IncidentStatus.MERGED:
                inhibitor.absorb(incident, keep_unexplained=True)
                self.stats.incidents_inhibited += 1
            else:
                self.stats.incidents_suppressed += 1
                self.stats.suppressed_logs += incident.log_events
            return []
        keys = (
            [_UNEXPLAINED_KEY]
            if incident.unexplained
            else [fp for fp in incident.fingerprints if fp and fp[0] in _DETECTOR_KINDS]
        )
        for key in keys:
            self._cooldown_index[key] = incident
            self._cooldown_index.move_to_end(key)
        while len(self._cooldown_index) > self._config.limits.max_open_incidents:
            self._cooldown_index.popitem(last=False)
        assessment = self._assessments.get(incident.id) or self._assess(incident)
        return [AlertEvent(AlertEventKind.RESOLVED, at, incident, assessment)]

    # ------------------------------------------------------------------ evaluation
    def _evaluate(self, incident: Incident, now: float, *, reopened: bool) -> list[AlertEvent]:
        if incident.alert is None and not self._could_alert(incident):
            return []  # cheap pre-check: most noise incidents never get near the bar
        stale = now - incident.evaluated_at >= self._reevaluate_after
        if (
            incident.alert is not None
            and not reopened
            and incident.evaluated_version == incident.structure_version
            and not stale
            and incident.max_severity <= incident.alert.severity
        ):
            return []
        assessment = self._assess(incident)
        incident.evaluated_version = incident.structure_version
        incident.evaluated_at = now
        self._assessments[incident.id] = assessment
        if not self._should_alert(incident, assessment):
            return []
        alert = incident.alert
        if alert is None:
            incident.alert = AlertState(
                alert_id=self._next_id(incident.opened_at),
                detected_at=now,
                severity=assessment.severity,
                title=assessment.title,
                root_cause=assessment.root.service,
                severity_history=[(now, assessment.severity)],
            )
            self._remember(incident)
            created = [AlertEvent(AlertEventKind.NEW, now, incident, assessment)]
            if incident.unexplained:
                created.extend(self._fold_into(incident, now))
            return created
        changed = False
        if assessment.severity > alert.severity:
            alert.severity = assessment.severity
            alert.severity_history.append((now, assessment.severity))
            changed = True
        if assessment.title != alert.title or assessment.root.service != alert.root_cause:
            alert.title = assessment.title
            alert.root_cause = assessment.root.service
            changed = True
        events: list[AlertEvent] = []
        if reopened:
            events.append(AlertEvent(AlertEventKind.REOPENED, now, incident, assessment))
        elif changed:
            events.append(AlertEvent(AlertEventKind.UPDATED, now, incident, assessment))
        if incident.unexplained:
            events.extend(self._fold_into(incident, now))
        return events

    def _fold_into(self, noise: Incident, now: float) -> list[AlertEvent]:
        """Re-classify open incidents that overlap active background noise.

        Alerts raised moments before the noise was recognised are merged into it
        (emitting MERGED), and quieter incidents are marked so that they fold in when
        they close.
        """
        events: list[AlertEvent] = []
        for incident in list(self._open):
            if incident is noise or incident.unexplained or not self._covers(noise, incident):
                continue
            if incident.alert is None:
                # Not alerting yet, so it cannot be corroborated/critical: only metric
                # evidence keeps it out of the noise (checked without running RCA).
                if (
                    self._config.correlation.inhibit_during_unexplained
                    and self._metric_evidence(incident) != "dense"
                ):
                    incident.inhibited_by = noise
                continue
            assessment = self._assessments.get(incident.id) or self._assess(incident)
            if not self._inhibitable(incident, assessment):
                continue
            events.append(AlertEvent(AlertEventKind.MERGED, now, incident, assessment))
            self._alerted.pop(incident.id, None)
            self._open.remove(incident)
            for fingerprint in incident.fingerprints:
                self._by_fingerprint[fingerprint] = noise
            noise.absorb(incident, keep_unexplained=True)
            self.stats.incidents_inhibited += 1
        return events

    def _assess(self, incident: Incident) -> Assessment:
        root = self._rca.analyze(incident)
        cascade = (
            self._cascade_severity is not None
            and not incident.unexplained
            and len(incident.cascade_members) >= self._config.thresholds.cascade_min_services
        )
        severity = incident.max_severity
        if cascade and self._cascade_severity is not None:
            severity = max(severity, self._cascade_severity)
        category = self._builder.category(incident, root, cascade)
        now = incident.last_activity
        context = RuleContext(
            incident=incident,
            root_cause=root.service,
            category=category,
            cascade=cascade,
            severity=severity,
            error_rate=lambda service: self._error_rate(service, now),
        )
        if incident.unexplained and self._is_diverse(incident):
            severity = min(severity, Severity.MEDIUM)
        # Rules describe correlated incidents; conditions such as "affected_services > 3"
        # are meaningless for the bucket of unrelated errors, so it is not evaluated.
        matched = () if incident.unexplained else tuple(self._rules.matching(context))
        for rule in matched:
            severity = max(severity, rule.severity)
        if incident.alert is not None:
            severity = max(severity, incident.alert.severity)  # never silently de-escalate
        category, title = self._builder.describe(incident, root, cascade, matched)
        return Assessment(root, cascade, severity, matched, category, title)

    def _could_alert(self, incident: Incident) -> bool:
        """Necessary (not sufficient) conditions for a first alert, without running RCA."""
        if incident.unexplained or _METRIC_DETECTORS & incident.kinds.keys():
            return True
        if len(incident.cascade_members) >= self._config.thresholds.cascade_min_services:
            return True
        needed = incident.min_occurrences_override or self._config.thresholds.min_occurrences
        if len(incident.services) > 1:
            return incident.burst(needed) <= self._grouping
        return incident.fingerprint_burst(needed) <= self._grouping

    def _should_alert(self, incident: Incident, assessment: Assessment) -> bool:
        if incident.alert is not None:
            return True
        if assessment.severity < self._config.thresholds.min_alert_severity:
            return False
        if self._inhibited(incident, assessment):
            return False
        # Metric detectors (latency trend, saturation) and the noise bucket alert on their
        # own; an error-rate spike adds evidence to an incident but never pages for it.
        if assessment.cascade or incident.unexplained or _METRIC_DETECTORS & incident.kinds.keys():
            return True
        needed = incident.min_occurrences_override or self._config.thresholds.min_occurrences
        if len(incident.services) > 1:
            # Several services linked by evidence: any `needed` related errors in a window.
            return incident.burst(needed) <= self._grouping
        # One service: the *same* error must repeat `needed` times within the window;
        # a mix of different random errors is the error-rate detector's job.
        return incident.fingerprint_burst(needed) <= self._grouping

    def _strong(self, incident: Incident, assessment: Assessment | None) -> bool:
        """Is the incident backed by evidence that random error lines cannot fake?

        * a metric detector fired (latency trend, resource saturation), or
        * its root cause is *corroborated*: the root reports the failure itself
          ("health check failed", "pool exhausted"), another service names it as the
          dependency it is failing on, **and** the failures arrive as a burst
          (``min_occurrences`` within the cascade window), or
        * it is CRITICAL with a root that logged its own failure.

        Strong incidents explain their services' error-rate spikes and are never
        absorbed into background noise. Roots that were only inferred from callers, or
        that merely blame someone else, are what random noise produces.
        """
        if incident.unexplained:
            return False
        metric = self._metric_evidence(incident)
        if metric == "dense" or (metric == "sparse" and not self._broad_noise_active()):
            return True
        if assessment is None or assessment.root.inferred:
            return False
        if assessment.severity >= Severity.CRITICAL:
            return True
        root = incident.services.get(assessment.root.service)
        named = any(dst == assessment.root.service for _src, dst in incident.edges)
        burst = incident.burst(self._config.thresholds.min_occurrences) <= self._cascade_window
        return root is not None and root.self_evidence >= 1.0 and named and burst

    @staticmethod
    def _metric_evidence(incident: Incident) -> str:
        """``dense`` (saturation, or a latency trend over real history), ``sparse`` (a
        latency trend judged from a handful of samples) or ``none``."""
        found = "none"
        for (_svc, kind), signal in incident.latest_detector.items():
            if kind == "resource_saturation" or (
                kind == "latency_degradation" and not signal.attributes.get("sparse")
            ):
                return "dense"
            if kind == "latency_degradation":
                found = "sparse"
        return found

    def _broad_noise_active(self) -> bool:
        return any(
            inc.unexplained and inc.alert is not None and self._covers(inc, inc)
            for inc in self._open
        )

    def _inhibitable(self, incident: Incident, assessment: Assessment) -> bool:
        """Weak incidents can be absorbed by active background noise; strong ones page."""
        return (
            self._config.correlation.inhibit_during_unexplained
            and not incident.unexplained
            and not self._strong(incident, assessment)
        )

    def _inhibited(self, incident: Incident, assessment: Assessment) -> bool:
        """Suppress a narrower alert while broad unexplained noise is active."""
        if not self._inhibitable(incident, assessment):
            return False
        for other in self._open:
            if other.unexplained and other.alert is not None and self._covers(other, incident):
                incident.inhibited_by = other
                return True
        return False

    def _covers(self, noise: Incident, incident: Incident) -> bool:
        """Only *broad* noise (several unrelated services) inhibits other incidents.

        A single service with an unexplained error rate is not "background noise"; its
        own incidents keep their specific alerts.
        """
        del incident  # coverage is platform-wide once the noise is broad
        return len(noise.services) >= self._config.thresholds.cascade_min_services

    def _is_diverse(self, incident: Incident) -> bool:
        if incident.log_events == 0:
            return True
        ratio = incident.unique_errors / incident.log_events
        return ratio >= self._config.thresholds.noise_diversity_ratio or len(incident.services) > 2

    def _remember(self, incident: Incident) -> None:
        self._alerted[incident.id] = incident
        limit = self._config.limits.max_retained_alerts
        while len(self._alerted) > limit:
            oldest_id, oldest = next(iter(self._alerted.items()))
            if oldest.status is IncidentStatus.OPEN:
                break
            self._alerted.pop(oldest_id)
            self._assessments.pop(oldest_id, None)
            self.stats.alerts_evicted += 1

    def _next_id(self, ts: float) -> str:
        day = format_date_compact(ts)
        self._sequence[day] = self._sequence.get(day, 0) + 1
        return f"ALR-{day}-{self._sequence[day]:03d}"


_DETECTOR_KINDS = frozenset({"error_rate_spike", "latency_degradation", "resource_saturation"})
_METRIC_DETECTORS = frozenset({"latency_degradation", "resource_saturation"})
