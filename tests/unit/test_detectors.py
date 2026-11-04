from __future__ import annotations

import random

import pytest

from log_analyzer.config import AnalyzerConfig, build_config
from log_analyzer.detectors import DETECTORS
from log_analyzer.detectors.base import BoundedState
from log_analyzer.detectors.error_rate import ErrorRateDetector
from log_analyzer.detectors.latency import LatencyDetector
from log_analyzer.detectors.saturation import SaturationDetector
from log_analyzer.models import Category, Level, Severity, Signal
from log_analyzer.processing.metrics import MetricExtractor
from tests.conftest import event

T0 = 1_700_000_000.0


def feed(detector: object, config: AnalyzerConfig, events: list) -> list[Signal]:  # type: ignore[type-arg]
    extractor = MetricExtractor(config.metrics)
    out: list[Signal] = []
    for e in events:
        out.extend(detector.observe(e, extractor.extract(e)))  # type: ignore[attr-defined]
    return out


def test_registry_has_builtins() -> None:
    assert {"error_rate", "latency", "saturation"} <= set(DETECTORS.names())


def test_bounded_state_evicts_least_recently_used() -> None:
    state: BoundedState[str, list[int]] = BoundedState(2, list)
    state.get("a").append(1)
    state.get("b")
    state.get("a")  # refresh a
    state.get("c")  # evicts b
    assert state.peek("b") is None
    assert state.peek("a") == [1]
    assert state.evictions == 1
    assert len(state) == 2
    assert [k for k, _ in state.items()] == ["a", "c"]


# --------------------------------------------------------------------------- error rate
class TestErrorRate:
    config = build_config(
        {"services": [{"name": "api", "critical": True, "expected_error_rate": 0.1}]}
    )

    def _traffic(self, start: float, seconds: int, per_second: int, error_every: int = 0) -> list:  # type: ignore[type-arg]
        events = []
        n = 0
        for s in range(seconds):
            for i in range(per_second):
                n += 1
                is_error = error_every and n % error_every == 0
                events.append(
                    event(
                        "boom" if is_error else "ok",
                        service="api",
                        level=Level.ERROR if is_error else Level.INFO,
                        ts=start + s + i / per_second,
                    )
                )
        return events

    def test_spike_over_learned_baseline(self) -> None:
        detector = ErrorRateDetector(self.config)
        quiet = self._traffic(T0, 300, 5)  # 5 minutes of clean traffic
        busy = self._traffic(T0 + 300, 30, 5, error_every=4)  # 25% errors
        signals = feed(detector, self.config, quiet + busy)
        assert signals
        first = signals[0]
        assert first.kind == "error_rate_spike"
        assert first.severity is Severity.HIGH  # critical service
        assert first.category is Category.AVAILABILITY
        assert first.attributes["baseline"] == pytest.approx(0.1)  # expected rate is the floor
        assert first.attributes["rate"] >= 3 * 0.1  # fires as soon as 3 errors land
        assert first.attributes["errors"] >= 3
        assert len(signals) <= 2  # heartbeats, not one signal per error
        snapshot = detector.snapshot("api", T0 + 330)
        assert snapshot.rate > 10
        assert snapshot.errors > 0

    def test_needs_min_occurrences(self) -> None:
        detector = ErrorRateDetector(self.config)
        events = [event("boom", service="api", ts=T0), event("boom", service="api", ts=T0 + 1)]
        assert feed(detector, self.config, events) == []

    def test_sustained_errors_are_not_absorbed_into_the_baseline(self) -> None:
        """Buckets seen during a spike are excluded from the baseline, so a long outage
        keeps being reported instead of quietly becoming "normal"."""
        detector = ErrorRateDetector(self.config)
        outage = self._traffic(T0, 600, 5, error_every=5)  # 20% errors for 10 minutes
        signals = feed(detector, self.config, outage)
        assert signals[-1].ts > T0 + 540
        assert signals[-1].attributes["baseline"] == pytest.approx(0.1)

    def test_chronic_error_level_is_declared_with_expected_error_rate(self) -> None:
        config = build_config({"services": [{"name": "api", "expected_error_rate": 20}]})
        detector = ErrorRateDetector(config)
        assert feed(detector, config, self._traffic(T0, 300, 5, error_every=5)) == []
        burst = self._traffic(T0 + 300, 60, 5, error_every=1)  # 100% errors
        signals = feed(detector, config, burst)
        assert signals
        assert signals[0].severity is Severity.MEDIUM  # not a critical service

    def test_out_of_order_and_stale_events(self) -> None:
        detector = ErrorRateDetector(self.config)
        feed(detector, self.config, [event("ok", service="api", level=Level.INFO, ts=T0 + 100)])
        feed(detector, self.config, [event("ok", service="api", level=Level.INFO, ts=T0 + 90)])
        assert detector.snapshot("api", T0 + 100, window_s=60).total == 2
        feed(detector, self.config, [event("ok", service="api", level=Level.INFO, ts=T0 - 9999)])
        assert detector.snapshot("api", T0 + 100, window_s=60).total == 2
        unknown = detector.snapshot("nope", T0)
        assert (unknown.rate, unknown.total) == (0.0, 0)


# ------------------------------------------------------------------------------ latency
class TestLatency:
    config = build_config()

    def _series(self, values: list[float], step: float = 1.0, service: str = "api") -> list:  # type: ignore[type-arg]
        return [
            event(
                f"Request processed in {v:.0f}ms",
                service=service,
                level=Level.INFO,
                ts=T0 + i * step,
            )
            for i, v in enumerate(values)
        ]

    def test_spec_scenario_2_sparse_monotonic_series(self) -> None:
        detector = LatencyDetector(self.config)
        signals = feed(detector, self.config, self._series([145, 178, 234, 567, 892], step=300))
        assert len(signals) == 1
        signal = signals[0]
        assert signal.severity is Severity.MEDIUM  # still below the 1000ms hard threshold
        assert signal.ts == T0 + 4 * 300
        assert signal.attributes["sparse"] is True
        assert signal.attributes["eta_to_threshold_s"] > 0

    def test_gradual_degradation_after_history(self) -> None:
        rng = random.Random(1)
        normal = [rng.uniform(80, 200) for _ in range(40)]
        rising = [230 + 11 * i + rng.uniform(-10, 10) for i in range(20)]
        detector = LatencyDetector(self.config)
        signals = feed(detector, self.config, self._series(normal + rising))
        assert signals
        assert signals[0].attributes["sparse"] is False
        assert signals[0].attributes["ratio"] >= 2
        assert signals[0].category is Category.PERFORMANCE

    def test_random_noise_and_single_spikes_do_not_alert(self) -> None:
        rng = random.Random(7)
        values = [rng.uniform(10, 300) for _ in range(200)]
        values[100] = 5000  # one very slow request
        detector = LatencyDetector(self.config)
        assert feed(detector, self.config, self._series(values)) == []

    def test_escalates_above_hard_threshold_then_recovers(self) -> None:
        detector = LatencyDetector(self.config)
        history = [100.0] * 20
        rising = [150.0 + 60 * i for i in range(20)]  # crosses 1000ms
        recovered = [100.0] * 40
        signals = feed(detector, self.config, self._series(history + rising + recovered))
        severities = [s.severity for s in signals]
        assert Severity.MEDIUM in severities
        assert Severity.HIGH in severities
        state = detector._series.peek(("api", "request_latency"))
        assert state is not None
        assert not state.degraded  # recovered: hysteresis cleared the state


# --------------------------------------------------------------------------- saturation
class TestSaturation:
    config = build_config()

    def _pool(self, used: list[int]) -> list:  # type: ignore[type-arg]
        return [
            event(
                f"Connection pool: {u}/100 active",
                service="database",
                level=Level.INFO,
                ts=T0 + i * 6,
            )
            for i, u in enumerate(used)
        ]

    def test_early_warning_with_eta_then_critical_then_exhausted(self) -> None:
        detector = SaturationDetector(self.config)
        signals = feed(detector, self.config, self._pool(list(range(50, 102, 2))))
        levels = [s.attributes["level"] for s in signals]
        assert levels[0] == "warning"
        assert signals[0].severity is Severity.MEDIUM
        assert signals[0].attributes["eta_to_exhaustion_s"] == pytest.approx(60, abs=10)
        assert "critical" in levels
        assert levels[-1] == "exhausted"
        assert signals[-1].severity is Severity.HIGH
        assert signals[-1].attributes["trend_start_pct"] == 50

    def test_flat_high_utilization_below_critical_is_not_a_warning(self) -> None:
        detector = SaturationDetector(self.config)
        assert feed(detector, self.config, self._pool([85, 84, 85, 83, 84])) == []

    def test_recovery_resets_level(self) -> None:
        detector = SaturationDetector(self.config)
        first = feed(detector, self.config, self._pool([96, 40]))
        again = feed(detector, self.config, self._pool([96]))
        assert len(first) == 1
        assert len(again) == 1  # re-escalates after recovering
