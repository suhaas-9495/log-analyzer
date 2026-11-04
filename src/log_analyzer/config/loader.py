"""Load, merge and validate configuration.

Precedence (lowest to highest):

1. packaged ``defaults.yaml`` (pattern library, metric extractors, spec alert rules)
2. the user's ``config.yaml``

Sections may live at the top level *or* under ``analyzer:`` - the problem statement
shows both styles, so both are accepted (defining the same section twice is an error).
``patterns``, ``metrics`` and ``alert_rules`` merge **by name**: a user entry with the
same name replaces the built-in one, ``enabled: false`` removes it, new entries are
evaluated before the built-ins. Unknown keys are rejected so typos never pass silently.
"""

from __future__ import annotations

import fnmatch
import re
from collections.abc import Iterable, Mapping
from importlib import resources
from pathlib import Path
from types import MappingProxyType
from typing import Any, cast
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

import yaml

from log_analyzer.config.schema import (
    AlertRule,
    AnalyzerConfig,
    ApiConfig,
    Comparison,
    ConditionGroup,
    CorrelationConfig,
    DetectorConfig,
    FilterConfig,
    LimitsConfig,
    MetricRule,
    OutputConfig,
    ParserConfig,
    PatternRule,
    Predicate,
    RcaWeights,
    ServiceConfig,
    ThresholdsConfig,
    WindowsConfig,
)
from log_analyzer.models import Category, Level, Severity
from log_analyzer.timeutil import parse_duration


class ConfigError(ValueError):
    """Raised for any invalid configuration, with a dotted path to the offending key."""

    def __init__(self, path: str, message: str) -> None:
        super().__init__(f"{path}: {message}" if path else message)
        self.path = path


SECTIONS = (
    "windows",
    "thresholds",
    "services",
    "patterns",
    "metrics",
    "alert_rules",
    "ignore_patterns",
    "filters",
    "parsers",
    "detectors",
    "correlation",
    "output",
    "api",
    "limits",
)
_NAMED_LISTS = ("patterns", "metrics", "alert_rules")
_CASCADE_CONDITION = re.compile(r"^multiple_services_failing_within_(\d+)_seconds$")
_COMPARISON = re.compile(r"^\s*(>=|<=|==|!=|>|<)?\s*(.+?)\s*$")


# --------------------------------------------------------------------------- public API
def load_config(path: str | Path | None = None) -> AnalyzerConfig:
    """Load the packaged defaults, overlay ``path`` (if given) and validate.

    Raises:
        ConfigError: if the file cannot be read or fails validation.
    """
    user: dict[str, Any] = {}
    if path is not None:
        user = _read_yaml_file(Path(path))
    return build_config(user)


def build_config(user: Mapping[str, Any] | None = None) -> AnalyzerConfig:
    """Validate an in-memory config mapping (merged over the packaged defaults)."""
    defaults = _normalise_sections(_load_defaults(), "defaults")
    overrides = _normalise_sections(dict(user or {}), "")
    return _build(_merge(defaults, overrides))


# ---------------------------------------------------------------------------- reading
def _read_yaml_file(path: Path) -> dict[str, Any]:
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise ConfigError(str(path), f"cannot read config file ({exc.strerror})") from exc
    return _parse_yaml(text, str(path))


def _parse_yaml(text: str, origin: str) -> dict[str, Any]:
    try:
        data = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise ConfigError(origin, f"invalid YAML: {exc}") from exc
    if data is None:
        return {}
    if not isinstance(data, dict):
        raise ConfigError(origin, "top level must be a mapping")
    return cast(dict[str, Any], data)


def _load_defaults() -> dict[str, Any]:
    text = resources.files("log_analyzer.config").joinpath("defaults.yaml").read_text("utf-8")
    return _parse_yaml(text, "defaults.yaml")


def _normalise_sections(data: dict[str, Any], origin: str) -> dict[str, Any]:
    """Flatten ``analyzer:`` into the root so both layouts in the spec are accepted."""
    result = {k: v for k, v in data.items() if k != "analyzer"}
    nested = data.get("analyzer")
    if nested is not None:
        if not isinstance(nested, dict):
            raise ConfigError(_join(origin, "analyzer"), "expected a mapping")
        for key, value in nested.items():
            if key in result:
                raise ConfigError(
                    _join(origin, key), "defined both at top level and under 'analyzer'"
                )
            result[key] = value
    unknown = sorted(set(result) - set(SECTIONS))
    if unknown:
        raise ConfigError(origin, f"unknown section(s) {unknown}; allowed: {', '.join(SECTIONS)}")
    return result


def _merge(defaults: dict[str, Any], user: dict[str, Any]) -> dict[str, Any]:
    merged = dict(defaults)
    for key, value in user.items():
        if key in _NAMED_LISTS:
            merged[key] = _merge_named(defaults.get(key) or [], value, key)
        elif isinstance(value, dict) and isinstance(merged.get(key), dict):
            merged[key] = {**merged[key], **value}
        else:
            merged[key] = value
    for key in _NAMED_LISTS:
        merged[key] = [item for item in merged.get(key) or [] if item.get("enabled", True)]
    return merged


def _merge_named(base: list[Any], override: Any, path: str) -> list[dict[str, Any]]:
    if override is None:
        return list(base)
    if not isinstance(override, list):
        raise ConfigError(path, "expected a list")
    replaced: dict[str, dict[str, Any]] = {}
    new: list[dict[str, Any]] = []
    for idx, item in enumerate(override):
        if not isinstance(item, dict) or not isinstance(item.get("name"), str):
            raise ConfigError(f"{path}[{idx}]", "each entry must be a mapping with a 'name'")
        if any(b.get("name") == item["name"] for b in base):
            replaced[item["name"]] = item
        else:
            new.append(item)
    kept = [replaced.get(b.get("name", ""), b) for b in base]
    return new + kept


# --------------------------------------------------------------------------- building
class _Section:
    """Typed accessor over a mapping that reports unknown keys on :meth:`finish`."""

    def __init__(self, data: Any, path: str) -> None:
        if data is None:
            data = {}
        if not isinstance(data, dict):
            raise ConfigError(path, "expected a mapping")
        self.data: dict[str, Any] = data
        self.path = path
        self._used: set[str] = set()

    def has(self, key: str) -> bool:
        return key in self.data

    def raw(self, key: str, default: Any = None) -> Any:
        self._used.add(key)
        return self.data.get(key, default)

    def p(self, key: str) -> str:
        return _join(self.path, key)

    def number(
        self, key: str, default: float, *, minimum: float | None = None, positive: bool = False
    ) -> float:
        value = self.raw(key, default)
        if isinstance(value, bool) or not isinstance(value, int | float):
            raise ConfigError(self.p(key), f"expected a number, got {value!r}")
        _check_bounds(self.p(key), float(value), minimum, positive)
        return float(value)

    def integer(self, key: str, default: int, *, minimum: int | None = None) -> int:
        value = self.raw(key, default)
        if isinstance(value, bool) or not isinstance(value, int):
            raise ConfigError(self.p(key), f"expected an integer, got {value!r}")
        _check_bounds(self.p(key), value, minimum, False)
        return value

    def duration(self, key: str, default: float) -> float:
        value = self.raw(key, default)
        try:
            return parse_duration(value)
        except ValueError as exc:
            raise ConfigError(self.p(key), str(exc)) from exc

    def boolean(self, key: str, default: bool) -> bool:
        value = self.raw(key, default)
        if not isinstance(value, bool):
            raise ConfigError(self.p(key), f"expected true/false, got {value!r}")
        return value

    def string(self, key: str, default: str | None = None, *, required: bool = False) -> str:
        value = self.raw(key, default)
        if value is None and required:
            raise ConfigError(self.p(key), "is required")
        if not isinstance(value, str) or (required and not value.strip()):
            raise ConfigError(self.p(key), f"expected a non-empty string, got {value!r}")
        return value

    def optional_string(self, key: str) -> str | None:
        if self.raw(key) is None:
            return None
        return self.string(key)

    def strings(self, key: str, default: Iterable[str] = ()) -> tuple[str, ...]:
        value = self.raw(key, list(default))
        if value is None:
            return ()
        if isinstance(value, str):
            value = [value]
        if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
            raise ConfigError(self.p(key), f"expected a list of strings, got {value!r}")
        return tuple(value)

    def level(self, key: str, default: Level) -> Level:
        value = self.raw(key, default.name)
        try:
            return Level.parse(str(value))
        except ValueError as exc:
            raise ConfigError(self.p(key), str(exc)) from exc

    def severity(self, key: str, default: Severity | None = None) -> Severity:
        value = self.raw(key, default.name if default else None)
        if value is None:
            raise ConfigError(self.p(key), "is required")
        try:
            return Severity.parse(str(value))
        except ValueError as exc:
            raise ConfigError(self.p(key), str(exc)) from exc

    def section(self, key: str) -> _Section:
        return _Section(self.raw(key), self.p(key))

    def sections(self, key: str) -> list[_Section]:
        value = self.raw(key, [])
        if value is None:
            return []
        if not isinstance(value, list):
            raise ConfigError(self.p(key), "expected a list")
        return [_Section(item, f"{self.p(key)}[{i}]") for i, item in enumerate(value)]

    def finish(self) -> None:
        unknown = sorted(set(self.data) - self._used)
        if unknown:
            raise ConfigError(self.path, f"unknown key(s): {', '.join(unknown)}")


def _build(data: dict[str, Any]) -> AnalyzerConfig:
    root = _Section(data, "")
    services = _build_services(root)
    config = AnalyzerConfig(
        windows=_build_windows(root.section("windows")),
        thresholds=_build_thresholds(root.section("thresholds")),
        services=services,
        patterns=_build_patterns(root),
        metrics=_build_metrics(root),
        alert_rules=_build_alert_rules(root),
        filters=_build_filters(root.section("filters"), root.strings("ignore_patterns")),
        parsers=_build_parsers(root.section("parsers")),
        detectors=_build_detectors(root.section("detectors")),
        correlation=_build_correlation(root.section("correlation")),
        output=_build_output(root.section("output")),
        api=_build_api(root.section("api")),
        limits=_build_limits(root.section("limits")),
    )
    root.finish()
    _cross_validate(config)
    return config


def _build_windows(s: _Section) -> WindowsConfig:
    d = WindowsConfig()
    cfg = WindowsConfig(
        **{name: s.duration(name, getattr(d, name)) for name in WindowsConfig.__slots__}
    )
    s.finish()
    return cfg


def _build_thresholds(s: _Section) -> ThresholdsConfig:
    d = ThresholdsConfig()
    ints = {
        "min_occurrences",
        "min_baseline_events",
        "latency_min_samples",
        "latency_window_samples",
        "latency_max_samples",
        "cascade_min_services",
    }
    values: dict[str, Any] = {}
    for name in ThresholdsConfig.__slots__:
        if name == "min_alert_severity":
            values[name] = s.severity(name, d.min_alert_severity)
        elif name in ints:
            values[name] = s.integer(name, getattr(d, name), minimum=1)
        else:
            values[name] = s.number(name, getattr(d, name), minimum=0)
    cfg = ThresholdsConfig(**values)
    s.finish()
    for name in ("latency_trend_min_tau", "latency_sustained_fraction", "noise_diversity_ratio"):
        if not 0 <= getattr(cfg, name) <= 1:
            raise ConfigError(_join("thresholds", name), "must be between 0 and 1")
    if cfg.latency_window_samples > cfg.latency_max_samples:
        raise ConfigError(
            "thresholds.latency_window_samples", "must not exceed latency_max_samples"
        )
    if cfg.cascade_min_services < 2:
        raise ConfigError("thresholds.cascade_min_services", "a cascade needs at least 2")
    return cfg


def _build_services(root: _Section) -> tuple[ServiceConfig, ...]:
    services: list[ServiceConfig] = []
    seen: set[str] = set()
    for s in root.sections("services"):
        name = s.string("name", required=True)
        if name in seen:
            raise ConfigError(s.p("name"), f"duplicate service {name!r}")
        seen.add(name)
        expected = s.raw("expected_error_rate")
        services.append(
            ServiceConfig(
                name=name,
                critical=s.boolean("critical", False),
                dependencies=s.strings("dependencies"),
                expected_error_rate=(
                    s.number("expected_error_rate", 0.0, minimum=0)
                    if expected is not None
                    else None
                ),
                aliases=tuple(a.lower() for a in s.strings("aliases")),
            )
        )
        s.finish()
    return tuple(services)


def _build_patterns(root: _Section) -> tuple[PatternRule, ...]:
    rules: list[PatternRule] = []
    seen: set[str] = set()
    for s in root.sections("patterns"):
        rule = _build_pattern(s)
        if rule.name in seen:
            raise ConfigError(s.p("name"), f"duplicate pattern {rule.name!r}")
        seen.add(rule.name)
        rules.append(rule)
    if sum(1 for r in rules if r.condition) > 1:
        raise ConfigError("patterns", "only one condition (cascade) rule may be defined")
    return tuple(rules)


def _build_pattern(s: _Section) -> PatternRule:
    name = s.string("name", required=True)
    s.raw("enabled")
    regex = _compile(s, "regex") if s.has("regex") else None
    keywords = s.strings("keywords")
    keyword_regex = (
        re.compile("|".join(re.escape(k) for k in keywords), re.IGNORECASE) if keywords else None
    )
    condition = s.optional_string("condition")
    condition_window: float | None = None
    if condition is not None:
        match = _CASCADE_CONDITION.match(condition)
        if match is None:
            raise ConfigError(
                s.p("condition"),
                f"unsupported condition {condition!r} "
                "(supported: multiple_services_failing_within_<N>_seconds)",
            )
        condition_window = float(match.group(1))
    value_field = s.optional_string("field")
    if regex is None and keyword_regex is None and condition is None and value_field is None:
        raise ConfigError(s.path, "needs one of: regex, keywords, field, condition")
    threshold = s.number("threshold", 0.0) if s.raw("threshold") is not None else None
    value_range = _build_range(s)
    captures = s.strings("captures")
    group_by = s.strings("group_by", ("service",))
    if regex is not None:
        _check_captures(s, regex, captures, threshold)
    default_category = Category.AVAILABILITY if condition else Category.APPLICATION
    try:
        category = Category.parse(s.string("category", default_category.value))
    except ValueError as exc:
        raise ConfigError(s.p("category"), str(exc)) from exc
    min_occ = s.raw("min_occurrences")
    rule = PatternRule(
        name=name,
        severity=s.severity("severity"),
        category=category,
        regex=regex,
        keywords=keywords,
        keyword_regex=keyword_regex,
        threshold=threshold,
        value_field=value_field,
        value_range=value_range,
        group_by=group_by,
        captures=captures,
        target=s.optional_string("target"),
        condition=condition,
        condition_window=condition_window,
        min_level=s.level("min_level", Level.WARN),
        min_occurrences=(
            s.integer("min_occurrences", 1, minimum=1) if min_occ is not None else None
        ),
        services=s.strings("services"),
        title=s.optional_string("title"),
        probable_cause=s.optional_string("probable_cause"),
        actions=s.strings("actions"),
        prefilter=(p.lower() if (p := s.optional_string("prefilter")) else None),
    )
    s.finish()
    return rule


def _check_captures(
    s: _Section, regex: re.Pattern[str], captures: tuple[str, ...], threshold: float | None
) -> None:
    if captures and len(captures) > regex.groups:
        raise ConfigError(
            s.p("captures"), f"names {len(captures)} groups but regex has {regex.groups}"
        )
    if threshold is not None and not (captures or regex.groupindex or regex.groups):
        raise ConfigError(s.p("threshold"), "regex needs a capture group holding the value")


def _build_range(s: _Section) -> tuple[float, float] | None:
    value = s.raw("value_range")
    if value is None:
        return None
    if (
        not isinstance(value, list)
        or len(value) != 2
        or not all(isinstance(v, int | float) and not isinstance(v, bool) for v in value)
        or value[0] > value[1]
    ):
        raise ConfigError(s.p("value_range"), "expected [min, max]")
    return float(value[0]), float(value[1])


def _build_metrics(root: _Section) -> tuple[MetricRule, ...]:
    metrics: list[MetricRule] = []
    for s in root.sections("metrics"):
        name = s.string("name", required=True)
        s.raw("enabled")
        kind = s.string("kind", required=True)
        if kind not in ("latency", "utilization"):
            raise ConfigError(s.p("kind"), "must be 'latency' or 'utilization'")
        required_groups = {"value"} if kind == "latency" else {"used", "capacity"}
        patterns = s.strings("regex")
        regexes: list[re.Pattern[str]] = []
        for i, text in enumerate(patterns):
            compiled = _compile_text(f"{s.p('regex')}[{i}]", text)
            missing = required_groups - set(compiled.groupindex)
            if missing:
                raise ConfigError(
                    f"{s.p('regex')}[{i}]", f"missing named group(s): {sorted(missing)}"
                )
            regexes.append(compiled)
        fields = s.strings("fields")
        if kind == "utilization" and fields and len(fields) != 2:
            raise ConfigError(s.p("fields"), "utilization needs [used_field, capacity_field]")
        if not regexes and not fields:
            raise ConfigError(s.path, "needs regex and/or fields")
        metrics.append(
            MetricRule(
                name=name,
                kind="latency" if kind == "latency" else "utilization",
                label=s.string("label", name.replace("_", " ")),
                regexes=tuple(regexes),
                fields=fields,
                prefilter=(p.lower() if (p := s.optional_string("prefilter")) else None),
                min_level=s.level("min_level", Level.DEBUG),
            )
        )
        s.finish()
    return tuple(metrics)


def _build_alert_rules(root: _Section) -> tuple[AlertRule, ...]:
    rules: list[AlertRule] = []
    for s in root.sections("alert_rules"):
        name = s.string("name", required=True)
        s.raw("enabled")
        rules.append(
            AlertRule(
                name=name,
                condition=_build_condition(s.raw("condition"), s.p("condition")),
                severity=s.severity("severity"),
                auto_escalate=s.boolean("auto_escalate", False),
                title=s.optional_string("title"),
                actions=s.strings("actions"),
            )
        )
        s.finish()
    return tuple(rules)


def _build_condition(value: Any, path: str) -> ConditionGroup:
    if not isinstance(value, dict) or len(value) != 1:
        raise ConfigError(path, "expected a mapping with a single 'all' or 'any' key")
    mode, items = next(iter(value.items()))
    if mode not in ("all", "any") or not isinstance(items, list) or not items:
        raise ConfigError(path, "expected 'all: [...]' or 'any: [...]' with at least one item")
    built: list[Predicate | ConditionGroup] = []
    for i, item in enumerate(items):
        item_path = f"{path}.{mode}[{i}]"
        if not isinstance(item, dict) or len(item) != 1:
            raise ConfigError(item_path, "each condition item must have exactly one key")
        key, raw = next(iter(item.items()))
        if key in ("all", "any"):
            built.append(_build_condition(item, item_path))
        else:
            built.append(_build_predicate(str(key), raw, f"{item_path}.{key}"))
    return ConditionGroup(mode="all" if mode == "all" else "any", items=tuple(built))


def _build_predicate(name: str, raw: Any, path: str) -> Predicate:
    if name == "pattern":
        return Predicate(name, text=str(raw), regex=_compile_text(path, str(raw), re.IGNORECASE))
    if name in ("service", "root_cause", "category"):
        if not isinstance(raw, str):
            raise ConfigError(path, "expected a string")
        return Predicate(name, text=raw)
    if name == "cascade":
        if not isinstance(raw, bool):
            raise ConfigError(path, "expected true/false")
        return Predicate(name, comparison=Comparison("==", 1.0 if raw else 0.0))
    if name in ("affected_services", "error_count", "unique_errors"):
        return Predicate(name, comparison=_comparison(raw, path, float))
    if name == "error_rate":
        return Predicate(name, comparison=_comparison(raw, path, _percent))
    if name == "duration":
        return Predicate(name, comparison=_comparison(raw, path, parse_duration))
    if name == "severity":
        return Predicate(
            name, comparison=_comparison(raw, path, lambda v: float(Severity.parse(v)))
        )
    raise ConfigError(
        path,
        "unknown predicate (supported: pattern, service, root_cause, category, cascade, "
        "affected_services, error_count, unique_errors, error_rate, duration, severity)",
    )


def _percent(text: str) -> float:
    return float(text.rstrip("%").strip())


def _comparison(raw: Any, path: str, convert: Any) -> Comparison:
    match = _COMPARISON.match(str(raw))
    if match is None:  # pragma: no cover - the regex matches any string
        raise ConfigError(path, f"invalid comparison {raw!r}")
    op = match.group(1) or ">="
    try:
        value = float(convert(match.group(2)))
    except (TypeError, ValueError) as exc:
        raise ConfigError(path, f"invalid comparison {raw!r}: {exc}") from exc
    return Comparison(op, value)


def _build_filters(s: _Section, ignore_patterns: tuple[str, ...]) -> FilterConfig:
    # Compiled one by one (not joined): patterns may carry their own inline flags, e.g. (?i).
    compiled = tuple(
        _compile_text(f"ignore_patterns[{i}]", pattern) for i, pattern in enumerate(ignore_patterns)
    )
    services = s.strings("ignore_services")
    cfg = FilterConfig(
        min_level=s.level("min_level", Level.INFO),
        ignore_services=services,
        ignore_patterns=ignore_patterns,
        ignore_regexes=compiled,
        ignore_service_regex=(
            re.compile("|".join(fnmatch.translate(g) for g in services), re.IGNORECASE)
            if services
            else None
        ),
    )
    s.finish()
    return cfg


def _build_parsers(s: _Section) -> ParserConfig:
    d = ParserConfig()
    tz = s.string("default_timezone", d.default_timezone)
    try:
        ZoneInfo(tz)
    except (ZoneInfoNotFoundError, ValueError) as exc:
        raise ConfigError(s.p("default_timezone"), f"unknown time zone {tz!r}") from exc
    channels = s.raw("app_channel_services", {}) or {}
    if not isinstance(channels, dict) or not all(
        isinstance(k, str) and isinstance(v, str) for k, v in channels.items()
    ):
        raise ConfigError(s.p("app_channel_services"), "expected a mapping of channel: service")
    cfg = ParserConfig(
        enabled=s.strings("enabled", d.enabled),
        plugins=s.strings("plugins"),
        default_timezone=tz,
        app_default_service=s.string("app_default_service", d.app_default_service),
        app_channel_services=MappingProxyType(dict(channels)),
        json_timestamp_keys=s.strings("json_timestamp_keys", d.json_timestamp_keys),
        json_level_keys=s.strings("json_level_keys", d.json_level_keys),
        json_service_keys=s.strings("json_service_keys", d.json_service_keys),
        json_message_keys=s.strings("json_message_keys", d.json_message_keys),
        json_request_id_keys=s.strings("json_request_id_keys", d.json_request_id_keys),
        max_line_length=s.integer("max_line_length", d.max_line_length, minimum=256),
    )
    s.finish()
    if not cfg.enabled:
        raise ConfigError("parsers.enabled", "at least one parser must be enabled")
    return cfg


def _build_detectors(s: _Section) -> DetectorConfig:
    d = DetectorConfig()
    cfg = DetectorConfig(enabled=s.strings("enabled", d.enabled), plugins=s.strings("plugins"))
    s.finish()
    return cfg


def _build_correlation(s: _Section) -> CorrelationConfig:
    keywords = s.strings("dependency_keywords")
    w = s.section("rca_weights")
    d = RcaWeights()
    weights = RcaWeights(
        reach=w.number("reach", d.reach, minimum=0),
        precedence=w.number("precedence", d.precedence, minimum=0),
        intrinsic=w.number("intrinsic", d.intrinsic, minimum=0),
    )
    w.finish()
    if weights.reach + weights.precedence + weights.intrinsic <= 0:
        raise ConfigError("correlation.rca_weights", "weights must not all be zero")
    cfg = CorrelationConfig(
        dependency_keywords=keywords,
        dependency_keyword_regex=(
            re.compile(r"\b(?:" + "|".join(re.escape(k) for k in keywords) + r")\b", re.I)
            if keywords
            else None
        ),
        rca_weights=weights,
        inhibit_during_unexplained=s.boolean("inhibit_during_unexplained", True),
    )
    s.finish()
    return cfg


def _build_output(s: _Section) -> OutputConfig:
    d = OutputConfig()
    color = s.string("color", d.color)
    if color not in ("auto", "always", "never"):
        raise ConfigError(s.p("color"), "must be auto, always or never")
    cfg = OutputConfig(
        max_sample_logs=s.integer("max_sample_logs", d.max_sample_logs, minimum=1),
        max_evidence=s.integer("max_evidence", d.max_evidence, minimum=1),
        max_actions=s.integer("max_actions", d.max_actions, minimum=1),
        max_trend_rows=s.integer("max_trend_rows", d.max_trend_rows, minimum=1),
        sample_log_max_chars=s.integer("sample_log_max_chars", d.sample_log_max_chars, minimum=40),
        refresh_seconds=s.duration("refresh_seconds", d.refresh_seconds),
        color="auto" if color == "auto" else ("always" if color == "always" else "never"),
    )
    s.finish()
    return cfg


def _build_api(s: _Section) -> ApiConfig:
    d = ApiConfig()
    cfg = ApiConfig(
        host=s.string("host", d.host),
        port=s.integer("port", d.port, minimum=0),
        max_body_bytes=s.integer("max_body_bytes", d.max_body_bytes, minimum=1024),
        max_lines=s.integer("max_lines", d.max_lines, minimum=1),
    )
    s.finish()
    if cfg.port > 65535:
        raise ConfigError("api.port", "must be <= 65535")
    return cfg


def _build_limits(s: _Section) -> LimitsConfig:
    d = LimitsConfig()
    cfg = LimitsConfig(
        **{name: s.integer(name, getattr(d, name), minimum=1) for name in LimitsConfig.__slots__}
    )
    s.finish()
    return cfg


def _cross_validate(config: AnalyzerConfig) -> None:
    w = config.windows
    if w.error_rate_current >= w.error_rate_baseline:
        raise ConfigError("windows.error_rate_current", "must be shorter than error_rate_baseline")
    if w.bucket_seconds > w.error_rate_current:
        raise ConfigError("windows.bucket_seconds", "must not exceed error_rate_current")
    for svc in config.services:
        if svc.name in svc.dependencies:
            raise ConfigError(f"services.{svc.name}", "a service cannot depend on itself")


# ---------------------------------------------------------------------------- helpers
def _compile(s: _Section, key: str) -> re.Pattern[str]:
    return _compile_text(s.p(key), s.string(key))


def _compile_text(path: str, text: str, flags: int = 0) -> re.Pattern[str]:
    try:
        return re.compile(text, flags)
    except re.error as exc:
        raise ConfigError(path, f"invalid regex {text!r}: {exc}") from exc


def _check_bounds(path: str, value: float, minimum: float | None, positive: bool) -> None:
    if minimum is not None and value < minimum:
        raise ConfigError(path, f"must be >= {minimum:g}")
    if positive and value <= 0:
        raise ConfigError(path, "must be > 0")


def _join(base: str, key: str) -> str:
    return f"{base}.{key}" if base else key
