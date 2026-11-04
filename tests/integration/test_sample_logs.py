"""End-to-end expectations on the sample data provided with the challenge."""

from __future__ import annotations

from pathlib import Path

import pytest

from log_analyzer.config import AnalyzerConfig
from log_analyzer.engine import AnalysisResult
from log_analyzer.models import Severity
from log_analyzer.output.report import report_dict
from tests.conftest import SAMPLE_10K, analyze_file

SPEC_ALERT_KEYS = [
    "alert_id", "severity", "title", "summary", "timeline", "impact",
    "root_cause_analysis", "suggested_actions", "sample_logs", "deduplication_stats",
]


def _assert_expected_incidents(result: AnalysisResult) -> None:
    by_category: dict[str, list[str]] = {}
    for alert in result.alerts:
        by_category.setdefault(alert.category, []).append(alert.root_service)

    critical = [a for a in result.alerts if a.severity is Severity.CRITICAL]
    assert {a.root_service for a in critical} == {"database", "payment-provider"}

    pool = next(a for a in critical if a.root_service == "database")
    assert pool.title == "Database Connection Crisis"
    assert pool.probable_cause == "Database connection pool exhausted"
    assert pool.confidence >= 0.9
    assert pool.auto_escalate
    assert {"order-service", "inventory-service", "payment-service", "user-service",
            "api-gateway"} <= set(pool.affected_services)

    cascade = next(a for a in critical if a.root_service == "payment-provider")
    assert cascade.cascade
    assert {"payment-service", "web-app"} <= set(cascade.affected_services)

    perf = [a for a in result.alerts if a.category == "performance"]
    assert len(perf) == 1
    assert perf[0].severity is Severity.MEDIUM
    assert perf[0].root_service == "database"

    noise = [a for a in result.alerts if a.category in ("error_rate", "errors")]
    assert len(noise) == 2  # one per band of random errors
    assert all(a.severity is Severity.MEDIUM and a.confidence <= 0.3 for a in noise)

    assert len(result.alerts) == 5
    assert result.noise_reduction >= 95.0


def test_10k_sample_produces_the_expected_alerts(config: AnalyzerConfig) -> None:
    result = analyze_file(SAMPLE_10K, config)

    assert result.stats.lines_read == 9998
    assert result.stats.unparsed == 0
    assert result.stats.filtered["below_min_level"] == 273  # DEBUG / dev noise
    _assert_expected_incidents(result)


def test_pool_exhaustion_is_flagged_before_the_pool_runs_out(config: AnalyzerConfig) -> None:
    result = analyze_file(SAMPLE_10K, config)
    pool = next(a for a in result.alerts if a.title == "Database Connection Crisis")
    history = pool.severity_history
    first_alert_at = history[0][0]
    exhausted_at = 1759847112.128  # 2025-10-07T14:25:12Z "Connection pool exhausted"

    assert first_alert_at < exhausted_at  # early warning from the saturation trend
    assert history[0][1] is Severity.MEDIUM
    assert history[-1][1] is Severity.CRITICAL
    assert any("rose from 50%" in line for line in pool.evidence)


@pytest.mark.perf
def test_100k_sample_produces_the_same_incidents(
    config: AnalyzerConfig, large_sample: Path
) -> None:
    result = analyze_file(large_sample, config)

    assert result.stats.lines_read == 99998
    _assert_expected_incidents(result)


def test_alerts_follow_the_spec_output_format(config: AnalyzerConfig) -> None:
    report = report_dict(analyze_file(SAMPLE_10K, config))

    assert list(report)[:3] == ["analysis_period", "statistics", "alerts"]
    assert {"total_logs", "errors_found", "alerts_generated", "noise_reduction_percent"} <= set(
        report["statistics"]
    )
    assert {"processing_time_ms", "memory_usage_mb"} <= set(report["metrics"])
    for alert in report["alerts"]:
        assert list(alert)[: len(SPEC_ALERT_KEYS)] == SPEC_ALERT_KEYS
        assert alert["alert_id"].startswith("ALR-20251007-")
        assert set(alert["timeline"]) == {
            "first_occurrence", "last_occurrence", "total_duration_seconds"
        }
        assert set(alert["impact"]) == {
            "affected_services", "error_count", "unique_errors", "estimated_failed_requests"
        }
        assert set(alert["root_cause_analysis"]) == {"probable_cause", "confidence", "evidence"}
        assert 0 < alert["root_cause_analysis"]["confidence"] <= 1
        assert alert["suggested_actions"][0].startswith("1. ")
        assert set(alert["deduplication_stats"]) == {
            "total_logs_analyzed", "logs_grouped", "noise_reduction_percent"
        }
