"""Resource saturation (connection pools and other used/capacity gauges).

Readings such as ``Connection pool: 95/100 active`` or JSON ``active_connections`` /
``max_connections`` become utilization ratios. Levels:

* **warning**   - utilization >= ``saturation_warning_ratio`` *and rising*  (MEDIUM)
* **critical**  - utilization >= ``saturation_critical_ratio``              (HIGH)
* **exhausted** - utilization >= 100%                                      (HIGH)

A signal is emitted on every escalation, plus a heartbeat while elevated. The warning
level includes a linear projection of time-to-exhaustion, which is how the analyzer
alerts *before* the pool runs out rather than after.
"""

from __future__ import annotations

import itertools
import math
from collections import deque
from collections.abc import Sequence
from dataclasses import dataclass

from log_analyzer.config.schema import AnalyzerConfig
from log_analyzer.detectors.base import DETECTORS, BoundedState
from log_analyzer.models import Category, LogEvent, Severity, Signal, SignalSource
from log_analyzer.processing.metrics import MetricSample
from log_analyzer.stats import slope

_MAX_READINGS = 32
_RISING_READINGS = 3
_LEVEL_NAMES = ("normal", "warning", "critical", "exhausted")


@dataclass(slots=True)
class _Gauge:
    readings: deque[tuple[float, float]]
    level: int = 0
    last_emit: float = -math.inf


class SaturationDetector:
    name = "saturation"

    def __init__(self, config: AnalyzerConfig) -> None:
        t = config.thresholds
        self._warning = t.saturation_warning_ratio
        self._critical = t.saturation_critical_ratio
        self._heartbeat = config.windows.alert_grouping / 2
        self._gauges: BoundedState[tuple[str, str], _Gauge] = BoundedState(
            config.limits.max_tracked_keys, lambda: _Gauge(deque(maxlen=_MAX_READINGS))
        )

    def observe(self, event: LogEvent, samples: Sequence[MetricSample]) -> list[Signal]:
        signals: list[Signal] = []
        for sample in samples:
            if sample.kind != "utilization":
                continue
            gauge = self._gauges.get((event.service, sample.metric))
            gauge.readings.append((event.ts, sample.value))
            level = self._level(gauge, sample.value)
            if level == 0:
                gauge.level = 0
                continue
            if level <= gauge.level and event.ts - gauge.last_emit < self._heartbeat:
                continue
            gauge.level = max(level, gauge.level)
            gauge.last_emit = event.ts
            signals.append(self._signal(event, sample, gauge, level))
        return signals

    def _level(self, gauge: _Gauge, ratio: float) -> int:
        if ratio >= 1.0:
            return 3
        if ratio >= self._critical:
            return 2
        if ratio >= self._warning and self._rising(gauge):
            return 1
        return 0

    @staticmethod
    def _rising(gauge: _Gauge) -> bool:
        recent = [v for _, v in list(gauge.readings)[-_RISING_READINGS:]]
        return len(recent) >= 2 and all(b >= a for a, b in itertools.pairwise(recent))

    def _signal(self, event: LogEvent, sample: MetricSample, gauge: _Gauge, level: int) -> Signal:
        readings = list(gauge.readings)
        low_ts, low = min(readings, key=lambda r: r[1])
        per_second = slope(readings[-8:])
        eta = (1.0 - sample.value) / per_second if per_second > 0 and sample.value < 1 else None
        pct = sample.value * 100
        usage = (
            f" ({sample.used:.0f}/{sample.capacity:.0f})"
            if sample.used is not None and sample.capacity is not None
            else ""
        )
        return Signal(
            kind="resource_saturation",
            source=SignalSource.DETECTOR,
            ts=event.ts,
            service=event.service,
            severity=Severity.MEDIUM if level == 1 else Severity.HIGH,
            category=Category.RESOURCE,
            fingerprint=("resource_saturation", event.service, sample.metric),
            template=f"{sample.label} saturation in {event.service}",
            event=event,
            attributes={
                "metric": sample.metric,
                "label": sample.label,
                "utilization_pct": round(pct, 1),
                "used": sample.used,
                "capacity": sample.capacity,
                "level": _LEVEL_NAMES[level],
                "trend_start_ts": low_ts,
                "trend_start_pct": round(low * 100, 1),
                "eta_to_exhaustion_s": round(eta, 1) if eta is not None else None,
            },
            title=f"{sample.label.capitalize()} {_LEVEL_NAMES[level]}",
            probable_cause=f"{sample.label.capitalize()} at {pct:.0f}%{usage}",
            actions=(
                "Find what is holding the resource (slow queries, leaks, traffic spike)",
                "Increase capacity (pool size / max connections) as an immediate mitigation",
            ),
        )


DETECTORS.register("saturation")(SaturationDetector)
