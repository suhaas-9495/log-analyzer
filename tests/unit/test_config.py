from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from log_analyzer.config import ConfigError, build_config, load_config
from log_analyzer.config.schema import ConditionGroup, Predicate
from log_analyzer.models import Category, Level, Severity
from tests.conftest import ROOT

CONFIGS = sorted((ROOT / "configs").rglob("*.yaml"))


def test_builtin_defaults_are_complete() -> None:
    config = build_config()
    names = [p.name for p in config.patterns]
    assert {
        "connection_timeout",
        "database_slow_query",
        "memory_exhaustion",
        "cascading_failure",
    } <= set(names)
    assert [r.name for r in config.alert_rules] == [
        "Database Connection Crisis",
        "API Gateway Cascade",
    ]
    assert config.filters.ignore_patterns == (
        "Health check endpoint",
        "Metrics collection",
        "DEBUG.*development",
    )
    assert config.cascade_rule is not None
    assert config.cascade_rule.condition_window == 30
    assert config.windows.error_rate_baseline == 300
    assert config.thresholds.min_occurrences == 3


@pytest.mark.parametrize("path", CONFIGS, ids=lambda p: p.name)
def test_every_shipped_config_is_valid(path: Path) -> None:
    load_config(path)


def test_spec_example_config_loads_verbatim() -> None:
    config = load_config(ROOT / "configs" / "spec-example.yaml")
    api = config.service("api-gateway")
    assert api is not None
    assert api.critical
    assert api.dependencies == ("auth-service", "payment-service", "inventory-service")
    assert config.expected_error_rate("api-gateway") == 0.1
    assert config.expected_error_rate("unknown") == config.thresholds.default_expected_error_rate
    assert config.is_critical("payment-service")
    assert not config.is_critical("background-worker")
    crisis = config.alert_rules[0]
    assert crisis.severity is Severity.CRITICAL
    assert crisis.auto_escalate
    first = crisis.condition.items[0]
    assert isinstance(first, Predicate)
    assert first.name == "pattern"
    second = crisis.condition.items[1]
    assert isinstance(second, Predicate)
    assert second.comparison is not None
    assert str(second.comparison) == ">3"


def test_spec_pattern_rule_shape_is_accepted() -> None:
    """The pattern rules exactly as written in the problem statement."""
    config = build_config(
        {
            "patterns": [
                {
                    "name": "connection_timeout",
                    "regex": "Connection timeout to ([\\w-]+)",
                    "severity": "HIGH",
                    "group_by": ["service", "target_service"],
                },
                {
                    "name": "database_slow_query",
                    "regex": "Query took (\\d+)ms",
                    "threshold": 1000,
                    "severity": "MEDIUM",
                },
                {
                    "name": "memory_exhaustion",
                    "keywords": ["OutOfMemoryError", "memory exhausted", "heap space"],
                    "severity": "CRITICAL",
                },
                {
                    "name": "cascading_failure",
                    "condition": "multiple_services_failing_within_30_seconds",
                    "severity": "CRITICAL",
                },
            ]
        }
    )
    by_name = {p.name: p for p in config.patterns}
    assert by_name["database_slow_query"].threshold == 1000
    assert by_name["memory_exhaustion"].severity is Severity.CRITICAL


def test_sections_at_top_level_or_under_analyzer() -> None:
    nested = build_config({"analyzer": {"thresholds": {"min_occurrences": 5}}})
    flat = build_config({"thresholds": {"min_occurrences": 5}})
    assert nested.thresholds.min_occurrences == flat.thresholds.min_occurrences == 5


def test_named_lists_merge_by_name() -> None:
    config = build_config(
        {
            "patterns": [
                {"name": "my_rule", "regex": "boom", "severity": "HIGH"},
                {"name": "rate_limited", "enabled": False},
                {
                    "name": "deadlock",
                    "regex": "(?i)deadlock",
                    "severity": "CRITICAL",
                    "category": "resource",
                },
            ],
        }
    )
    names = [p.name for p in config.patterns]
    assert names[0] == "my_rule"  # new rules are evaluated before the built-ins
    assert "rate_limited" not in names
    deadlock = next(p for p in config.patterns if p.name == "deadlock")
    assert deadlock.severity is Severity.CRITICAL
    assert names.index("deadlock") > names.index("db_pool_exhausted")  # keeps its position


def test_durations_levels_and_overrides() -> None:
    config = build_config(
        {
            "windows": {"error_rate_baseline": "10m", "alert_grouping": "90s"},
            "filters": {"min_level": "warning", "ignore_services": ["dev-*"]},
            "thresholds": {"min_alert_severity": "low"},
            "patterns": [
                {
                    "name": "x",
                    "regex": "x",
                    "severity": "low",
                    "min_occurrences": 1,
                    "category": "SECURITY",
                    "min_level": "info",
                    "prefilter": "X",
                }
            ],
        }
    )
    assert config.windows.error_rate_baseline == 600
    assert config.windows.alert_grouping == 90
    assert config.filters.min_level is Level.WARN
    assert config.thresholds.min_alert_severity is Severity.LOW
    rule = config.patterns[0]
    assert rule.min_occurrences == 1
    assert rule.category is Category.SECURITY
    assert rule.min_level is Level.INFO
    assert rule.prefilter == "x"


def test_load_config_from_file(tmp_path: Path) -> None:
    path = tmp_path / "c.yaml"
    path.write_text("analyzer:\n  thresholds:\n    min_occurrences: 7\n")
    assert load_config(path).thresholds.min_occurrences == 7
    empty = tmp_path / "empty.yaml"
    empty.write_text("")
    assert load_config(empty).thresholds.min_occurrences == 3


def test_condition_groups_nest() -> None:
    config = build_config(
        {
            "alert_rules": [
                {
                    "name": "nested",
                    "severity": "HIGH",
                    "condition": {
                        "any": [
                            {"cascade": True},
                            {"all": [{"severity": ">=HIGH"}, {"unique_errors": "5"}]},
                        ]
                    },
                }
            ]
        }
    )
    rule = next(r for r in config.alert_rules if r.name == "nested")
    assert rule.condition.mode == "any"
    inner = rule.condition.items[1]
    assert isinstance(inner, ConditionGroup)
    unique = inner.items[1]
    assert isinstance(unique, Predicate)
    assert unique.comparison is not None
    assert unique.comparison.op == ">="  # bare numbers default to ">="


@pytest.mark.parametrize(
    ("data", "message"),
    [
        ({"bogus": 1}, "unknown section"),
        ({"thresholds": {"min_occurence": 3}}, "unknown key(s): min_occurence"),
        ({"thresholds": {"min_occurrences": "three"}}, "expected an integer"),
        ({"thresholds": {"min_occurrences": 0}}, "must be >= 1"),
        ({"thresholds": {"error_rate_multiplier": True}}, "expected a number"),
        ({"thresholds": {"latency_trend_min_tau": 2}}, "between 0 and 1"),
        ({"thresholds": {"cascade_min_services": 1}}, "at least 2"),
        ({"thresholds": {"latency_window_samples": 100}}, "must not exceed"),
        ({"windows": {"alert_grouping": "soon"}}, "invalid duration"),
        ({"windows": {"error_rate_current": 600}}, "shorter than error_rate_baseline"),
        ({"windows": {"bucket_seconds": 120}}, "must not exceed error_rate_current"),
        ({"services": [{"name": "a"}, {"name": "a"}]}, "duplicate service"),
        ({"services": [{"name": "a", "dependencies": ["a"]}]}, "cannot depend on itself"),
        ({"services": [{"critical": True}]}, "services[0].name: is required"),
        ({"services": "nope"}, "expected a list"),
        ({"patterns": [{"name": "x", "severity": "HIGH"}]}, "needs one of"),
        ({"patterns": [{"name": "x", "regex": "(", "severity": "HIGH"}]}, "invalid regex"),
        ({"patterns": [{"name": "x", "regex": "x", "severity": "LOUD"}]}, "unknown severity"),
        (
            {"patterns": [{"name": "x", "regex": "x", "severity": "HIGH", "category": "z"}]},
            "unknown category",
        ),
        (
            {"patterns": [{"name": "x", "condition": "moon_is_full", "severity": "HIGH"}]},
            "unsupported condition",
        ),
        (
            {"patterns": [{"name": "x", "regex": "x", "threshold": 5, "severity": "HIGH"}]},
            "capture group",
        ),
        (
            {
                "patterns": [
                    {"name": "x", "regex": "(a)", "captures": ["a", "b"], "severity": "HIGH"}
                ]
            },
            "names 2 groups",
        ),
        (
            {
                "patterns": [
                    {"name": "x", "regex": "(\\d+)", "value_range": [5, 1], "severity": "HIGH"}
                ]
            },
            "expected [min, max]",
        ),
        (
            {
                "patterns": [
                    {"name": "x", "regex": "x", "severity": "HIGH"},
                    {"name": "x", "regex": "y", "severity": "HIGH"},
                ]
            },
            "duplicate pattern",
        ),
        (
            {
                "patterns": [
                    {
                        "name": "c2",
                        "condition": "multiple_services_failing_within_9_seconds",
                        "severity": "HIGH",
                    }
                ]
            },
            "only one condition",
        ),
        ({"patterns": ["just a string"]}, "must be a mapping with a 'name'"),
        ({"patterns": {"name": "x"}}, "expected a list"),
        ({"metrics": [{"name": "m", "kind": "speed", "regex": "x"}]}, "'latency' or"),
        ({"metrics": [{"name": "m", "kind": "latency", "regex": "(\\d+)"}]}, "missing named group"),
        (
            {"metrics": [{"name": "m", "kind": "utilization", "fields": ["a"]}]},
            "used_field, capacity_field",
        ),
        ({"metrics": [{"name": "m", "kind": "latency"}]}, "needs regex and/or fields"),
        (
            {"alert_rules": [{"name": "r", "severity": "HIGH", "condition": {"all": []}}]},
            "at least one item",
        ),
        (
            {"alert_rules": [{"name": "r", "severity": "HIGH", "condition": {"all": [{"x": 1}]}}]},
            "unknown predicate",
        ),
        (
            {
                "alert_rules": [
                    {
                        "name": "r",
                        "severity": "HIGH",
                        "condition": {"all": [{"duration": ">later"}]},
                    }
                ]
            },
            "invalid comparison",
        ),
        (
            {
                "alert_rules": [
                    {"name": "r", "severity": "HIGH", "condition": {"all": [{"service": 5}]}}
                ]
            },
            "expected a string",
        ),
        (
            {
                "alert_rules": [
                    {"name": "r", "severity": "HIGH", "condition": {"all": [{"cascade": "yes"}]}}
                ]
            },
            "true/false",
        ),
        (
            {"alert_rules": [{"name": "r", "severity": "HIGH", "condition": "x"}]},
            "single 'all' or 'any'",
        ),
        (
            {
                "alert_rules": [
                    {"name": "r", "severity": "HIGH", "condition": {"all": [{"a": 1, "b": 2}]}}
                ]
            },
            "exactly one key",
        ),
        ({"alert_rules": [{"name": "r", "condition": {"all": [{"service": "a"}]}}]}, "is required"),
        ({"ignore_patterns": ["("]}, "invalid regex"),
        ({"filters": {"min_level": "chatty"}}, "unknown log level"),
        ({"parsers": {"default_timezone": "Mars/Base"}}, "unknown time zone"),
        ({"parsers": {"app_channel_services": ["x"]}}, "channel: service"),
        ({"parsers": {"enabled": []}}, "at least one parser"),
        ({"parsers": {"enabled": "json", "max_line_length": 10}}, "must be >= 256"),
        ({"output": {"color": "rainbow"}}, "auto, always or never"),
        ({"api": {"port": 70000}}, "<= 65535"),
        (
            {"correlation": {"rca_weights": {"reach": 0, "precedence": 0, "intrinsic": 0}}},
            "must not all be zero",
        ),
        ({"correlation": {"inhibit_during_unexplained": "sometimes"}}, "true/false"),
        ({"analyzer": "x"}, "expected a mapping"),
        ({"analyzer": {"windows": {}}, "windows": {}}, "defined both"),
    ],
)
def test_invalid_configs_are_rejected_with_a_path(data: dict[str, Any], message: str) -> None:
    with pytest.raises(ConfigError) as info:
        build_config(data)
    assert message in str(info.value)


def test_unreadable_and_malformed_files(tmp_path: Path) -> None:
    with pytest.raises(ConfigError, match="cannot read"):
        load_config(tmp_path / "missing.yaml")
    bad = tmp_path / "bad.yaml"
    bad.write_text("analyzer: [unclosed")
    with pytest.raises(ConfigError, match="invalid YAML"):
        load_config(bad)
    scalar = tmp_path / "scalar.yaml"
    scalar.write_text("just a string")
    with pytest.raises(ConfigError, match="top level must be a mapping"):
        load_config(scalar)
