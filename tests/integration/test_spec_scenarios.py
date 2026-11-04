"""The four test scenarios from the problem statement, with its exact log lines."""

from __future__ import annotations

import json
import subprocess
import sys
import time
from pathlib import Path

import pytest

from log_analyzer.config import AnalyzerConfig
from log_analyzer.models import Severity
from log_analyzer.testdata.generator import GeneratorSettings, generate
from log_analyzer.timeutil import parse_timestamp
from tests.conftest import CONFIG_PATH, FIXTURES, analyze, analyze_file


def test_scenario_1_cascade_yields_single_critical_alert_rooted_in_database(
    config: AnalyzerConfig,
) -> None:
    result = analyze_file(FIXTURES / "scenario1_cascade.log", config)

    assert len(result.alerts) == 1
    alert = result.alerts[0]
    assert alert.severity is Severity.CRITICAL
    assert alert.root_service == "database"
    assert alert.confidence >= 0.9
    assert set(alert.affected_services) == {
        "database", "payment-service", "api-gateway", "web-app", "order-service",
    }
    assert alert.cascade


def test_scenario_1_with_843_more_related_errors_is_still_one_alert(
    config: AnalyzerConfig,
) -> None:
    """'# ... 843 more related errors' - the volume must not create more alerts."""
    base = (FIXTURES / "scenario1_cascade.log").read_text().splitlines()
    templates = [
        "ERROR [payment-service] Connection pool exhausted",
        "ERROR [api-gateway] Connection timeout to payment-service",
        "ERROR [web-app] Payment request failed",
        "ERROR [order-service] Cannot process order: payment unavailable",
    ]
    extra = []
    for i in range(843):
        second = 18 + i * 0.2  # 843 errors over ~3 minutes
        minute, sec = divmod(second, 60)
        extra.append(f"2024-01-10 10:{1 + int(minute):02d}:{sec:06.3f} {templates[i % 4]}")

    result = analyze(base + extra, config)

    assert len(result.alerts) == 1
    alert = result.alerts[0]
    assert alert.severity is Severity.CRITICAL
    assert alert.root_service == "database"
    assert result.noise_reduction > 99.0
    assert alert.to_dict()["deduplication_stats"]["noise_reduction_percent"] > 99.0


def test_scenario_2_degradation_alerts_medium_before_the_timeout(
    config: AnalyzerConfig,
) -> None:
    lines = (FIXTURES / "scenario2_degradation.log").read_text().splitlines()
    timeout_at = parse_timestamp("2024-01-10 09:25:00")

    result = analyze(lines, config)

    degradation = [a for a in result.alerts if a.category == "performance"]
    assert len(degradation) == 1
    alert = degradation[0]
    assert alert.severity is Severity.MEDIUM
    assert alert.detected_at < timeout_at  # alerted *before* failure occurred
    assert alert.root_service == "api"


def test_scenario_3_dev_logs_are_ignored_and_production_issue_alerts(
    config: AnalyzerConfig,
) -> None:
    result = analyze_file(FIXTURES / "scenario3_dev_noise.log", config)

    assert result.stats.ignored == 3  # three DEBUG lines from dev-server/localhost
    assert len(result.alerts) == 1
    alert = result.alerts[0]
    assert "production-api" in alert.affected_services
    assert not {"dev-server", "localhost"} & set(alert.affected_services)
    assert alert.severity >= Severity.HIGH
    assert {s.name for s in result.services} == {"production-api"}


@pytest.mark.perf
def test_scenario_4_high_volume_100k_lines(tmp_path: Path) -> None:
    """100,000 lines: < 5 s, < 100 MB, correct alerts, >= 95% noise reduction.

    Runs the real CLI in a fresh interpreter so time and peak memory are measured for
    the whole process, exactly as a user would run it.
    """
    log_file = tmp_path / "high_volume.log"
    with log_file.open("w", encoding="utf-8") as handle:
        written = generate(GeneratorSettings(lines=100_000, seed=4), handle)
    assert written >= 99_000

    started = time.perf_counter()
    completed = subprocess.run(
        [sys.executable, "-m", "log_analyzer", "--file", str(log_file),
         "--config", str(CONFIG_PATH), "--format", "json"],
        capture_output=True, text=True, check=True, timeout=60,
    )
    wall_seconds = time.perf_counter() - started
    report = json.loads(completed.stdout)

    assert report["metrics"]["processing_time_ms"] < 5_000
    assert wall_seconds < 5.0 + 1.5  # generous margin for interpreter start-up on CI
    assert report["metrics"]["memory_usage_mb"] < 100
    assert report["statistics"]["noise_reduction_percent"] >= 95.0
    titles = {(a["severity"], a["root_cause_service"]) for a in report["alerts"]}
    assert ("CRITICAL", "database") in titles
    assert ("CRITICAL", "payment-provider") in titles
    assert any(a["category"] == "performance" for a in report["alerts"])
    assert len(report["alerts"]) <= 8
