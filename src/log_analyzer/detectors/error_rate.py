"""Error-rate spike detection (spec: "Error Rate Spike Detection").

Per service, events are counted into fixed-size time buckets held in a ring buffer.
The *current* rate (last ``windows.error_rate_current`` seconds) is compared with a
*baseline* learned over the preceding ``windows.error_rate_baseline`` seconds:

    spike  <=>  errors_now >= min_occurrences
                and (rate_now >= multiplier * baseline  or  rate_now >= absolute threshold)

``baseline`` is never lower than the service's configured ``expected_error_rate``, so a
perfectly clean history does not make the very first error look like an infinite spike.
The absolute threshold only applies to services whose expected rate is below it (a
service declared to run at 20% errors is not "on fire" at 15%).
Buckets observed during a spike are flagged and excluded from future baselines, so a
long incident does not quietly become "the new normal".
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


@dataclass(slots=True)
class _Bucket:
    index: int
    total: int = 0
    errors: int = 0
    anomalous: bool = False


@dataclass(slots=True)
class _ServiceWindow:
    buckets: deque[_Bucket] = field(default_factory=deque)
    spiking: bool = False
    last_emit: float = -math.inf


@dataclass(frozen=True, slots=True)
class RateSnapshot:
    rate: float  # percent, current window
    baseline: float  # percent
    errors: int
    total: int


class ErrorRateDetector:
    name = "error_rate"

    def __init__(self, config: AnalyzerConfig) -> None:
        self._config = config
        w, t = config.windows, config.thresholds
        self._bucket_s = w.bucket_seconds
        self._current_n = max(1, math.ceil(w.error_rate_current / w.bucket_seconds))
        self._baseline_n = max(1, math.ceil(w.error_rate_baseline / w.bucket_seconds))
        retention_s = max(w.error_rate_baseline + w.error_rate_current, w.dashboard)
        self._retention_n = math.ceil(retention_s / w.bucket_seconds) + 1
        self._heartbeat = w.alert_grouping / 2
        self._multiplier = t.error_rate_multiplier
        self._absolute = t.error_rate_absolute_percent
        self._min_errors = t.min_occurrences
        self._min_baseline_events = t.min_baseline_events
        self._windows: BoundedState[str, _ServiceWindow] = BoundedState(
            config.limits.max_tracked_keys, _ServiceWindow
        )

    # ------------------------------------------------------------------------ API
    def observe(self, event: LogEvent, samples: Sequence[MetricSample]) -> list[Signal]:
        del samples
        state = self._windows.get(event.service)
        bucket = self._bucket(state, int(event.ts // self._bucket_s))
        if bucket is None:
            return []  # older than the retained window: too late to matter
        bucket.total += 1
        if not event.is_error:
            return []
        bucket.errors += 1
        return self._evaluate(event.service, state, event.ts)

    def snapshot(self, service: str, now: float, window_s: float | None = None) -> RateSnapshot:
        """Current error rate for ``service`` (used by alert rules and the dashboard)."""
        state = self._windows.peek(service)
        expected = self._config.expected_error_rate(service)
        if state is None:
            return RateSnapshot(0.0, expected, 0, 0)
        n = self._current_n if window_s is None else max(1, math.ceil(window_s / self._bucket_s))
        now_idx = int(now // self._bucket_s)
        errors, total = self._sum(state, now_idx - n + 1, now_idx + 1, include_anomalous=True)
        return RateSnapshot(
            rate=100.0 * errors / total if total else 0.0,
            baseline=self._baseline(service, state, now_idx - n + 1),
            errors=errors,
            total=total,
        )

    # -------------------------------------------------------------------- internals
    def _bucket(self, state: _ServiceWindow, index: int) -> _Bucket | None:
        buckets = state.buckets
        if not buckets or index > buckets[-1].index:
            buckets.append(_Bucket(index))
            while buckets and buckets[0].index <= index - self._retention_n:
                buckets.popleft()
            return buckets[-1]
        for bucket in reversed(buckets):  # out-of-order event: walk back (rarely far)
            if bucket.index == index:
                return bucket
            if bucket.index < index:
                break
        if index <= buckets[-1].index - self._retention_n:
            return None
        new = _Bucket(index)
        position = sum(1 for b in buckets if b.index < index)
        buckets.insert(position, new)
        return new

    @staticmethod
    def _sum(
        state: _ServiceWindow, start: int, end: int, *, include_anomalous: bool
    ) -> tuple[int, int]:
        errors = total = 0
        for bucket in state.buckets:
            if start <= bucket.index < end and (include_anomalous or not bucket.anomalous):
                errors += bucket.errors
                total += bucket.total
        return errors, total

    def _baseline(self, service: str, state: _ServiceWindow, current_start: int) -> float:
        expected = self._config.expected_error_rate(service)
        errors, total = self._sum(
            state, current_start - self._baseline_n, current_start, include_anomalous=False
        )
        if total < self._min_baseline_events:
            return expected
        return max(expected, 100.0 * errors / total)

    def _evaluate(self, service: str, state: _ServiceWindow, ts: float) -> list[Signal]:
        now_idx = int(ts // self._bucket_s)
        start = now_idx - self._current_n + 1
        errors, total = self._sum(state, start, now_idx + 1, include_anomalous=True)
        rate = 100.0 * errors / total if total else 0.0
        baseline = self._baseline(service, state, start)
        absolute_applies = self._absolute > self._config.expected_error_rate(service)
        spike = errors >= self._min_errors and (
            rate >= self._multiplier * baseline or (absolute_applies and rate >= self._absolute)
        )
        if not spike:
            state.spiking = False
            return []
        for bucket in state.buckets:
            if bucket.index >= start:
                bucket.anomalous = True
        if state.spiking and ts - state.last_emit < self._heartbeat:
            return []
        state.spiking = True
        state.last_emit = ts
        critical = self._config.is_critical(service)
        return [
            Signal(
                kind="error_rate_spike",
                source=SignalSource.DETECTOR,
                ts=ts,
                service=service,
                severity=Severity.HIGH if critical else Severity.MEDIUM,
                category=Category.AVAILABILITY,
                fingerprint=("error_rate_spike", service),
                template=f"error rate spike in {service}",
                attributes={
                    "rate": round(rate, 2),
                    "baseline": round(baseline, 3),
                    "errors": errors,
                    "total": total,
                    "window_seconds": self._current_n * self._bucket_s,
                },
                title="Increased Error Rate",
                probable_cause=f"Error rate {rate:.1f}% vs {baseline:.2g}% baseline",
            )
        ]


DETECTORS.register("error_rate")(ErrorRateDetector)
