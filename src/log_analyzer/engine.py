"""The analysis pipeline.

    line -> parse -> filter -> classify + extract metrics -> detectors -> correlate -> alerts

:class:`Analyzer` is the single entry point used by the CLI (file and stdin), the HTTP
API and the tests. It is incremental: feed lines one at a time and receive alert
lifecycle events as they happen, or feed a whole file and call :meth:`Analyzer.result`.
All state is bounded, so the same object can run indefinitely on a live stream.
"""

from __future__ import annotations

import re
import time
from collections import Counter, OrderedDict
from collections.abc import Iterable
from dataclasses import dataclass, field

from log_analyzer.alerts.builder import AlertView
from log_analyzer.config.schema import AnalyzerConfig
from log_analyzer.correlation.correlator import AlertEvent, Correlator
from log_analyzer.correlation.topology import ServiceDirectory
from log_analyzer.detectors import DETECTORS, Detector
from log_analyzer.detectors.error_rate import ErrorRateDetector
from log_analyzer.ingest.parsers import ParserChain
from log_analyzer.models import Level, LogEvent, Severity, Signal
from log_analyzer.plugins import PluginError, load_reference
from log_analyzer.processing.classifier import PatternClassifier
from log_analyzer.processing.filters import EventFilter
from log_analyzer.processing.metrics import MetricExtractor

# Multi-line stack-trace continuations are not parse errors.
_CONTINUATION = re.compile(r"^(?:\s+\S|at\s|Caused by:|Traceback|\.\.\. \d+ more)")
_MAX_UNPARSED_SAMPLES = 5
_ADVANCE_EVERY_S = 1.0
_TIMELINE_BUCKET_S = 10.0


@dataclass(slots=True)
class ServiceCounters:
    events: int = 0
    errors: int = 0
    warnings: int = 0
    first_ts: float = 0.0
    last_ts: float = 0.0


@dataclass(slots=True)
class RunStats:
    lines_read: int = 0
    blank_lines: int = 0
    parsed: int = 0
    unparsed: int = 0
    continuation_lines: int = 0
    truncated_lines: int = 0
    analyzed: int = 0
    errors: int = 0
    warnings: int = 0
    signals: int = 0
    filtered: Counter[str] = field(default_factory=Counter)
    by_level: Counter[str] = field(default_factory=Counter)
    by_format: Counter[str] = field(default_factory=Counter)
    unparsed_samples: list[str] = field(default_factory=list)
    first_ts: float | None = None
    last_ts: float | None = None

    @property
    def ignored(self) -> int:
        return sum(self.filtered.values())


@dataclass(frozen=True, slots=True)
class ServiceSummary:
    name: str
    events: int
    errors: int
    warnings: int
    error_rate: float  # percent over the reporting window
    expected_rate: float  # percent
    trend_percent: float | None  # change vs expected; None if no traffic
    status: str  # CRITICAL / DEGRADED / WARNING / HEALTHY


@dataclass(frozen=True, slots=True)
class AnalysisResult:
    stats: RunStats
    period_start: float | None
    period_end: float | None
    window_errors: int
    window_events: int
    alerts: list[AlertView]
    services: list[ServiceSummary]
    processing_seconds: float
    peak_memory_mb: float

    @property
    def noise_reduction(self) -> float:
        """Share of error lines that did *not* page anyone: 1 - alerts / errors."""
        if self.window_errors == 0:
            return 100.0 if not self.alerts else 0.0
        return round(100.0 * max(0.0, 1 - len(self.alerts) / self.window_errors), 1)


class _Timeline:
    """Per-service counts in fixed buckets, for window-scoped dashboards (bounded)."""

    def __init__(self, max_buckets: int) -> None:
        self._buckets: OrderedDict[int, dict[str, list[int]]] = OrderedDict()
        self._max = max_buckets

    def add(self, event: LogEvent) -> None:
        index = int(event.ts // _TIMELINE_BUCKET_S)
        bucket = self._buckets.get(index)
        if bucket is None:
            bucket = {}
            self._buckets[index] = bucket
            if len(self._buckets) > self._max:
                self._buckets.popitem(last=False)
        counts = bucket.setdefault(event.service, [0, 0, 0])
        counts[0] += 1
        if event.level >= Level.ERROR:
            counts[1] += 1
        elif event.level is Level.WARN:
            counts[2] += 1

    def window(self, start: float, end: float) -> dict[str, list[int]]:
        totals: dict[str, list[int]] = {}
        first, last = int(start // _TIMELINE_BUCKET_S), int(end // _TIMELINE_BUCKET_S)
        for index, bucket in self._buckets.items():
            if first <= index <= last:
                for service, (events, errors, warnings) in bucket.items():
                    acc = totals.setdefault(service, [0, 0, 0])
                    acc[0] += events
                    acc[1] += errors
                    acc[2] += warnings
        return totals


class Analyzer:
    def __init__(self, config: AnalyzerConfig) -> None:
        self.config = config
        self.stats = RunStats()
        self.directory = ServiceDirectory(config, config.limits.max_tracked_keys)
        self._parsers = ParserChain(config.parsers)
        self._filter = EventFilter(config.filters)
        self._metrics = MetricExtractor(config.metrics)
        self._classifier = PatternClassifier(config, self.directory)
        self._detectors = self._load_detectors(config)
        self._error_rate = next(
            (d for d in self._detectors if isinstance(d, ErrorRateDetector)), None
        )
        self.correlator = Correlator(config, self.directory, self._rate_lookup)
        self._services: OrderedDict[str, ServiceCounters] = OrderedDict()
        self._timeline = _Timeline(config.limits.max_timeline_buckets)
        self._watermark = float("-inf")
        self._next_advance = float("-inf")
        self._started = time.perf_counter()

    # ------------------------------------------------------------------------ input
    def process_line(self, line: str) -> list[AlertEvent]:
        stats = self.stats
        stats.lines_read += 1
        line = line.rstrip("\r\n")
        if not line.strip():
            stats.blank_lines += 1
            return []
        if len(line) > self._parsers.max_line_length:
            stats.truncated_lines += 1
            line = line[: self._parsers.max_line_length]
        event = self._parsers.parse(line, stats.lines_read)
        if event is None:
            if _CONTINUATION.match(line):
                stats.continuation_lines += 1
            else:
                stats.unparsed += 1
                if len(stats.unparsed_samples) < _MAX_UNPARSED_SAMPLES:
                    stats.unparsed_samples.append(line[:200])
            return []
        return self.process_event(event)

    def process_lines(self, lines: Iterable[str]) -> list[AlertEvent]:
        events: list[AlertEvent] = []
        for line in lines:
            events.extend(self.process_line(line))
        return events

    def process_event(self, event: LogEvent) -> list[AlertEvent]:
        stats = self.stats
        stats.parsed += 1
        stats.by_format[event.fmt] += 1
        reason = self._filter.reason(event)
        if reason is not None:
            stats.filtered[reason.value] += 1
            return []
        self._count(event)
        self.directory.observe(event.service)
        if event.ts > self._watermark:
            self._watermark = event.ts
        signals: list[Signal] = []
        signal = self._classifier.classify(event)
        if signal is not None:
            signals.append(signal)
        samples = self._metrics.extract(event)
        for detector in self._detectors:
            signals.extend(detector.observe(event, samples))
        alert_events: list[AlertEvent] = []
        for item in signals:
            stats.signals += 1
            alert_events.extend(self.correlator.ingest(item))
        if not signals:
            if event.level >= Level.WARN:
                self.correlator.attach_context(event)
            if self._watermark >= self._next_advance:
                alert_events.extend(self.correlator.advance(self._watermark))
                self._next_advance = self._watermark + _ADVANCE_EVERY_S
        return alert_events

    def advance_clock(self, now: float) -> list[AlertEvent]:
        """Advance event time without new input (e.g. an idle live stream)."""
        if now > self._watermark:
            self._watermark = now
        return self.correlator.advance(self._watermark)

    @property
    def watermark(self) -> float | None:
        return None if self._watermark == float("-inf") else self._watermark

    # ----------------------------------------------------------------------- output
    def result(self, window_s: float | None = None) -> AnalysisResult:
        """Snapshot of the analysis; ``window_s`` limits it to the trailing window."""
        stats = self.stats
        end = stats.last_ts
        start = stats.first_ts
        if window_s is not None and end is not None:
            start = max(start or end, end - window_s)
        builder = self.correlator.builder
        views: list[AlertView] = []
        for incident, assessment in self.correlator.alerts():
            if start is not None and incident.last_activity < start:
                continue
            views.append(builder.build(incident, assessment))
        views.sort(key=lambda v: (-v.severity, v.first_ts))
        if window_s is None:
            counts = {
                name: [c.events, c.errors, c.warnings] for name, c in self._services.items()
            }
        else:
            counts = self._timeline.window(start or 0.0, end or 0.0)
        services = self._summaries(counts, views)
        return AnalysisResult(
            stats=stats,
            period_start=start,
            period_end=end,
            window_errors=sum(c[1] for c in counts.values()),
            window_events=sum(c[0] for c in counts.values()),
            alerts=views,
            services=services,
            processing_seconds=time.perf_counter() - self._started,
            peak_memory_mb=peak_memory_mb(),
        )

    # -------------------------------------------------------------------- internals
    def _count(self, event: LogEvent) -> None:
        stats = self.stats
        stats.analyzed += 1
        stats.by_level[event.level.name] += 1
        if stats.first_ts is None or event.ts < stats.first_ts:
            stats.first_ts = event.ts
        if stats.last_ts is None or event.ts > stats.last_ts:
            stats.last_ts = event.ts
        counters = self._services.get(event.service)
        if counters is None:
            counters = ServiceCounters(first_ts=event.ts, last_ts=event.ts)
            self._services[event.service] = counters
            if len(self._services) > self.config.limits.max_tracked_keys:
                self._services.popitem(last=False)
        counters.events += 1
        counters.last_ts = max(counters.last_ts, event.ts)
        if event.level >= Level.ERROR:
            stats.errors += 1
            counters.errors += 1
        elif event.level is Level.WARN:
            stats.warnings += 1
            counters.warnings += 1
        self._timeline.add(event)

    def _summaries(
        self, counts: dict[str, list[int]], alerts: list[AlertView]
    ) -> list[ServiceSummary]:
        worst: dict[str, Severity] = {}
        for view in alerts:
            for service in view.affected_services:
                worst[service] = max(worst.get(service, Severity.LOW), view.severity)
        multiplier = self.config.thresholds.error_rate_multiplier
        summaries: list[ServiceSummary] = []
        for name, (events, errors, warnings) in counts.items():
            expected = self.config.expected_error_rate(name)
            rate = 100.0 * errors / events if events else 0.0
            trend = ((rate - expected) / expected * 100.0) if events and expected > 0 else None
            severity = worst.get(name)
            if severity is Severity.CRITICAL:
                status = "CRITICAL"
            elif severity is Severity.HIGH:
                status = "DEGRADED"
            elif severity is not None or (errors and rate > multiplier * expected):
                status = "WARNING"
            else:
                status = "HEALTHY"
            summaries.append(
                ServiceSummary(name, events, errors, warnings, rate, expected, trend, status)
            )
        summaries.sort(key=lambda s: (-s.errors, s.name))
        return summaries

    def _rate_lookup(self, service: str, now: float) -> float:
        if self._error_rate is None:
            return 0.0
        return self._error_rate.snapshot(service, now).rate

    @staticmethod
    def _load_detectors(config: AnalyzerConfig) -> list[Detector]:
        detectors: list[Detector] = [DETECTORS.get(name)(config) for name in config.detectors.enabled]
        for reference in config.detectors.plugins:
            factory = load_reference(reference)
            if not callable(factory):
                raise PluginError(f"detector plugin {reference!r} is not callable")
            detectors.append(factory(config))
        return detectors


def peak_memory_mb() -> float:
    """Peak resident set size of this process in MB (0 where unsupported)."""
    try:
        import resource  # noqa: PLC0415 - POSIX only
    except ImportError:  # pragma: no cover - Windows
        return 0.0
    import sys  # noqa: PLC0415

    peak = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    divisor = 1024 * 1024 if sys.platform == "darwin" else 1024  # bytes on macOS, KiB on Linux
    return round(peak / divisor, 1)
