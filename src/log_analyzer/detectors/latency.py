"""Gradual performance degradation (spec: "Performance Degradation").

For every (service, latency metric) a bounded series of recent samples is kept. With
``W = latency_window_samples`` (the most recent samples) the series is *degrading* when:

1. **elevated**   - median of the newest half of the window >= ``ratio`` x baseline median
2. **sustained**  - most of those newest samples (``sustained_fraction``) are elevated,
                    so one slow request is not enough
3. **trending**   - Kendall's tau over the window >= ``trend_min_tau`` and its
                    Mann-Kendall z-score >= ``trend_min_z``: values rise *monotonically*
                    and significantly. This is what separates a gradual degradation from
                    random slow requests (the sample data has both), and lets a short but
                    perfectly monotonic series qualify while a short noisy one does not
4. the newest median is above ``latency_floor_ms`` (2ms -> 5ms is not an incident)

The baseline is the median of older samples in the series (or the start of the window
when there is no history). It is frozen while degraded so the slowdown is never
absorbed into "normal". Severity is MEDIUM while below
``performance_degradation_ms`` (alerting *before* failure) and HIGH above it. A
least-squares slope projects when the hard threshold will be crossed.
"""

from __future__ import annotations

import math
from collections import deque
from collections.abc import Sequence
from dataclasses import dataclass, field

from log_analyzer.config.schema import AnalyzerConfig
from log_analyzer.detectors.base import DETECTORS, BoundedState
from log_analyzer.models import Category, LogEvent, Severity, Signal, SignalSource
from log_analyzer.processing.metrics import MetricSample
from log_analyzer.stats import kendall_tau, kendall_z, median, percentile, slope

_HINT_REFRESH = 16
_CLEAR_FACTOR = 0.75  # hysteresis: leave the degraded state only well below the trigger


@dataclass(slots=True)
class _Series:
    samples: deque[tuple[float, float]]
    degraded: bool = False
    frozen_baseline: float | None = None
    severity: Severity | None = None
    last_emit: float = -math.inf
    baseline_hint: float | None = None
    since_hint: int = 0


@dataclass(frozen=True, slots=True)
class _Assessment:
    baseline: float
    current: float
    ratio: float
    sustained: float
    tau: float
    p95: float
    window: list[tuple[float, float]] = field(default_factory=list)


class LatencyDetector:
    name = "latency"

    def __init__(self, config: AnalyzerConfig) -> None:
        t, w = config.thresholds, config.windows
        self._max_age = w.latency_trend
        self._heartbeat = w.alert_grouping / 2
        self._min_samples = t.latency_min_samples
        self._window = t.latency_window_samples
        self._ratio = t.latency_degradation_ratio
        self._tau = t.latency_trend_min_tau
        self._z = t.latency_trend_min_z
        self._sustained = t.latency_sustained_fraction
        self._floor = t.latency_floor_ms
        self._hard_threshold = t.performance_degradation_ms
        max_samples = t.latency_max_samples
        self._series: BoundedState[tuple[str, str], _Series] = BoundedState(
            config.limits.max_tracked_keys, lambda: _Series(deque(maxlen=max_samples))
        )

    def observe(self, event: LogEvent, samples: Sequence[MetricSample]) -> list[Signal]:
        signals: list[Signal] = []
        for sample in samples:
            if sample.kind != "latency":
                continue
            series = self._series.get((event.service, sample.metric))
            series.samples.append((event.ts, sample.value))
            while series.samples and series.samples[0][0] < event.ts - self._max_age:
                series.samples.popleft()
            signal = self._update(event, sample, series)
            if signal is not None:
                signals.append(signal)
        return signals

    # -------------------------------------------------------------------- internals
    def _update(self, event: LogEvent, sample: MetricSample, series: _Series) -> Signal | None:
        if len(series.samples) < self._min_samples:
            return None
        series.since_hint += 1
        if series.baseline_hint is None or series.since_hint >= _HINT_REFRESH:
            series.baseline_hint = median([v for _, v in series.samples])
            series.since_hint = 0
        # Cheap gate: a normal-looking sample cannot start a degradation.
        if not series.degraded and sample.value < self._ratio * series.baseline_hint * 0.9:
            return None
        assessment = self._assess(series)
        if assessment is None:
            return None
        if series.degraded:
            if assessment.ratio < self._ratio * _CLEAR_FACTOR:
                series.degraded = False
                series.frozen_baseline = None
                series.severity = None
                return None
        elif self._is_degrading(assessment):
            series.degraded = True
            series.frozen_baseline = assessment.baseline
        else:
            return None
        severity = Severity.HIGH if assessment.current >= self._hard_threshold else Severity.MEDIUM
        escalated = series.severity is None or severity > series.severity
        if not escalated and event.ts - series.last_emit < self._heartbeat:
            return None
        series.severity = max(severity, series.severity or severity)
        series.last_emit = event.ts
        return self._signal(event, sample, assessment, severity)

    def _assess(self, series: _Series) -> _Assessment | None:
        points = list(series.samples)
        size = min(self._window, len(points))
        window = points[-size:]
        history = [v for _, v in points[:-size]]
        values = [v for _, v in window]
        if series.frozen_baseline is not None:
            baseline = series.frozen_baseline
        elif len(history) >= self._min_samples:
            baseline = median(history)
        else:
            baseline = median(values[: max(1, size // 3)])
        if baseline <= 0:
            return None
        recent = values[-max(2, size // 2) :]
        current = median(recent)
        elevated = sum(1 for v in recent if v >= self._ratio * baseline)
        return _Assessment(
            baseline=baseline,
            current=current,
            ratio=current / baseline,
            sustained=elevated / len(recent),
            tau=kendall_tau(values),
            p95=percentile(recent, 95),
            window=window,
        )

    def _is_degrading(self, a: _Assessment) -> bool:
        return (
            a.ratio >= self._ratio
            and a.sustained >= self._sustained
            and a.tau >= self._tau
            and kendall_z(a.tau, len(a.window)) >= self._z
            and a.current >= self._floor
        )

    def _signal(
        self, event: LogEvent, sample: MetricSample, a: _Assessment, severity: Severity
    ) -> Signal:
        per_second = slope(a.window)
        eta: float | None = None
        last = a.window[-1][1]
        if per_second > 0 and last < self._hard_threshold:
            eta = (self._hard_threshold - last) / per_second
        return Signal(
            kind="latency_degradation",
            source=SignalSource.DETECTOR,
            ts=event.ts,
            service=event.service,
            severity=severity,
            category=Category.PERFORMANCE,
            fingerprint=("latency_degradation", event.service, sample.metric),
            template=f"{sample.label} degradation in {event.service}",
            event=event,
            attributes={
                "metric": sample.metric,
                "label": sample.label,
                "baseline_ms": round(a.baseline, 1),
                "current_ms": round(a.current, 1),
                "p95_ms": round(a.p95, 1),
                "ratio": round(a.ratio, 2),
                "trend_tau": round(a.tau, 2),
                "slope_ms_per_s": round(per_second, 2),
                "eta_to_threshold_s": round(eta, 1) if eta is not None else None,
                "threshold_ms": self._hard_threshold,
                "window_start": a.window[0][0],
            },
            title=f"Performance Degradation ({sample.label})",
            probable_cause=(
                f"{sample.label.capitalize()} rising: {a.current:.0f}ms vs "
                f"{a.baseline:.0f}ms baseline ({a.ratio:.1f}x)"
            ),
            actions=(
                "Check recent deployments and traffic changes for the slow component",
                "Inspect slow-query logs / query plans and dependency latency",
                "Scale out or shed load before latency reaches the timeout threshold",
            ),
        )


DETECTORS.register("latency")(LatencyDetector)
