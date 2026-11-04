"""Typed, immutable configuration objects.

Everything tunable lives here; the defaults below mirror ``defaults.yaml`` so that a
partially specified customer config (such as the example in the problem statement)
still yields a fully working analyzer.
"""

from __future__ import annotations

import operator
import re
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Literal

from log_analyzer.models import Category, Level, Severity

MetricKind = Literal["latency", "utilization"]


@dataclass(frozen=True, slots=True)
class WindowsConfig:
    """Time windows, in seconds. The first three keys come straight from the spec."""

    error_rate_baseline: float = 300.0  # sliding window used to learn the normal error rate
    alert_grouping: float = 60.0  # an incident stays open while related signals arrive this often
    pattern_detection: float = 30.0  # cascade window: failures this close together are one cascade
    error_rate_current: float = 60.0  # "current" error-rate window compared against the baseline
    latency_trend: float = 1800.0  # max age of latency samples kept for trend detection
    alert_cooldown: float = 900.0  # a resolved alert re-opens (not re-fires) within this period
    noise_hold: float = 900.0  # broad noise stays "active" this long after its last spike
    bucket_seconds: float = 5.0  # resolution of the error-rate ring buffers
    dashboard: float = 300.0  # default live-dashboard window in streaming mode


@dataclass(frozen=True, slots=True)
class ThresholdsConfig:
    error_rate_multiplier: float = 3.0
    min_occurrences: int = 3
    performance_degradation_ms: float = 1000.0
    error_rate_absolute_percent: float = 10.0
    min_baseline_events: int = 20
    default_expected_error_rate: float = 1.0  # percent, used when a service has no config
    latency_degradation_ratio: float = 2.0
    latency_min_samples: int = 4
    latency_window_samples: int = 20
    latency_trend_min_tau: float = 0.5
    latency_trend_min_z: float = 2.3
    latency_sustained_fraction: float = 0.7
    latency_floor_ms: float = 100.0
    latency_max_samples: int = 64
    saturation_warning_ratio: float = 0.8
    saturation_critical_ratio: float = 0.95
    cascade_min_services: int = 3
    noise_diversity_ratio: float = 0.5
    min_alert_severity: Severity = Severity.MEDIUM  # incidents below this never page


@dataclass(frozen=True, slots=True)
class ServiceConfig:
    name: str
    critical: bool = False
    dependencies: tuple[str, ...] = ()
    expected_error_rate: float | None = None  # percent
    aliases: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class PatternRule:
    """A log pattern rule (spec section 2, "Pattern Matching Rules")."""

    name: str
    severity: Severity
    category: Category
    regex: re.Pattern[str] | None = None
    keywords: tuple[str, ...] = ()
    keyword_regex: re.Pattern[str] | None = None
    threshold: float | None = None
    value_field: str | None = None
    value_range: tuple[float, float] | None = None
    group_by: tuple[str, ...] = ("service",)
    captures: tuple[str, ...] = ()
    target: str | None = None
    condition: str | None = None
    condition_window: float | None = None
    min_level: Level = Level.WARN
    min_occurrences: int | None = None
    services: tuple[str, ...] = ()
    title: str | None = None
    probable_cause: str | None = None
    actions: tuple[str, ...] = ()
    prefilter: str | None = None

    @property
    def is_condition(self) -> bool:
        return self.condition is not None


@dataclass(frozen=True, slots=True)
class MetricRule:
    """Extracts a numeric metric (latency or utilization) from log events."""

    name: str
    kind: MetricKind
    label: str
    regexes: tuple[re.Pattern[str], ...] = ()
    fields: tuple[str, ...] = ()
    prefilter: str | None = None
    min_level: Level = Level.DEBUG


_OPERATORS: Mapping[str, Callable[[float, float], bool]] = MappingProxyType(
    {
        ">": operator.gt,
        ">=": operator.ge,
        "<": operator.lt,
        "<=": operator.le,
        "==": operator.eq,
        "!=": operator.ne,
    }
)


@dataclass(frozen=True, slots=True)
class Comparison:
    op: str
    value: float

    def test(self, observed: float) -> bool:
        return _OPERATORS[self.op](observed, self.value)

    def __str__(self) -> str:
        return f"{self.op}{self.value:g}"


@dataclass(frozen=True, slots=True)
class Predicate:
    """One leaf of an alert-rule condition, e.g. ``affected_services: ">3"``."""

    name: str
    text: str | None = None
    regex: re.Pattern[str] | None = None
    comparison: Comparison | None = None


@dataclass(frozen=True, slots=True)
class ConditionGroup:
    mode: Literal["all", "any"]
    items: tuple[Predicate | ConditionGroup, ...]


@dataclass(frozen=True, slots=True)
class AlertRule:
    name: str
    condition: ConditionGroup
    severity: Severity
    auto_escalate: bool = False
    title: str | None = None
    actions: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class FilterConfig:
    min_level: Level = Level.INFO
    ignore_services: tuple[str, ...] = ()  # glob patterns, e.g. "dev-*"
    ignore_patterns: tuple[str, ...] = ()  # regexes matched against the raw line
    ignore_regexes: tuple[re.Pattern[str], ...] = ()
    ignore_service_regex: re.Pattern[str] | None = None


@dataclass(frozen=True, slots=True)
class ParserConfig:
    enabled: tuple[str, ...] = ("json", "text", "app")
    plugins: tuple[str, ...] = ()
    default_timezone: str = "UTC"
    app_default_service: str = "app"
    app_channel_services: Mapping[str, str] = field(default_factory=lambda: MappingProxyType({}))
    json_timestamp_keys: tuple[str, ...] = ("timestamp", "@timestamp", "time", "ts")
    json_level_keys: tuple[str, ...] = ("level", "severity", "lvl", "log.level")
    json_service_keys: tuple[str, ...] = ("service", "service.name", "app", "logger")
    json_message_keys: tuple[str, ...] = ("message", "msg", "log")
    json_request_id_keys: tuple[str, ...] = ("request_id", "requestId", "trace_id", "traceId")
    max_line_length: int = 65536


@dataclass(frozen=True, slots=True)
class RcaWeights:
    reach: float = 0.45
    precedence: float = 0.25
    intrinsic: float = 0.30


@dataclass(frozen=True, slots=True)
class CorrelationConfig:
    dependency_keywords: tuple[str, ...] = ()
    dependency_keyword_regex: re.Pattern[str] | None = None
    rca_weights: RcaWeights = field(default_factory=RcaWeights)
    # While an "elevated errors, no common cause" alert is active, suppress smaller
    # non-critical alerts on the same services and fold their logs into it.
    inhibit_during_unexplained: bool = True


@dataclass(frozen=True, slots=True)
class DetectorConfig:
    enabled: tuple[str, ...] = ("error_rate", "latency", "saturation")
    plugins: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class OutputConfig:
    max_sample_logs: int = 5
    max_evidence: int = 6
    max_actions: int = 5
    max_trend_rows: int = 15
    sample_log_max_chars: int = 300
    refresh_seconds: float = 5.0
    color: Literal["auto", "always", "never"] = "auto"


@dataclass(frozen=True, slots=True)
class ApiConfig:
    host: str = "0.0.0.0"
    port: int = 8080
    max_body_bytes: int = 10 * 1024 * 1024
    max_lines: int = 200_000


@dataclass(frozen=True, slots=True)
class LimitsConfig:
    """Hard caps that keep memory bounded regardless of input size or cardinality."""

    max_tracked_keys: int = 10_000
    max_open_incidents: int = 1_000
    max_request_ids: int = 10_000
    max_fingerprints: int = 2_000
    max_retained_alerts: int = 5_000
    max_timeline_buckets: int = 1_440


@dataclass(frozen=True, slots=True)
class AnalyzerConfig:
    windows: WindowsConfig = field(default_factory=WindowsConfig)
    thresholds: ThresholdsConfig = field(default_factory=ThresholdsConfig)
    services: tuple[ServiceConfig, ...] = ()
    patterns: tuple[PatternRule, ...] = ()
    metrics: tuple[MetricRule, ...] = ()
    alert_rules: tuple[AlertRule, ...] = ()
    filters: FilterConfig = field(default_factory=FilterConfig)
    parsers: ParserConfig = field(default_factory=ParserConfig)
    detectors: DetectorConfig = field(default_factory=DetectorConfig)
    correlation: CorrelationConfig = field(default_factory=CorrelationConfig)
    output: OutputConfig = field(default_factory=OutputConfig)
    api: ApiConfig = field(default_factory=ApiConfig)
    limits: LimitsConfig = field(default_factory=LimitsConfig)
    _service_index: Mapping[str, ServiceConfig] = field(
        default_factory=lambda: MappingProxyType({}), repr=False, compare=False
    )

    def __post_init__(self) -> None:
        index = {svc.name: svc for svc in self.services}
        object.__setattr__(self, "_service_index", MappingProxyType(index))

    def service(self, name: str) -> ServiceConfig | None:
        return self._service_index.get(name)

    def is_critical(self, name: str) -> bool:
        svc = self._service_index.get(name)
        return svc.critical if svc else False

    def expected_error_rate(self, name: str) -> float:
        """Expected error rate for ``name`` in percent."""
        svc = self._service_index.get(name)
        if svc is not None and svc.expected_error_rate is not None:
            return svc.expected_error_rate
        return self.thresholds.default_expected_error_rate

    @property
    def cascade_rule(self) -> PatternRule | None:
        for rule in self.patterns:
            if rule.condition is not None:
                return rule
        return None
