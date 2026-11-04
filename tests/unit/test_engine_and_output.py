from __future__ import annotations

import json

from log_analyzer.config import AnalyzerConfig, build_config
from log_analyzer.correlation.correlator import AlertEventKind
from log_analyzer.engine import Analyzer, peak_memory_mb
from log_analyzer.output.console import ConsoleRenderer, use_color
from log_analyzer.output.report import event_json, report_dict, report_json
from tests.conftest import FIXTURES, TOPOLOGY, analyze


def test_line_statistics(config: AnalyzerConfig) -> None:
    analyzer = Analyzer(build_config({"parsers": {"max_line_length": 256}}))
    lines = [
        "",
        "   ",
        "garbage that is not a log line",
        "    at com.example.Foo.bar(Foo.java:42)",
        "Caused by: java.io.IOException",
        "2024-01-10 10:00:00 DEBUG [svc] ignored by level",
        "2024-01-10 10:00:01 INFO [svc] " + "x" * 400,
        "2024-01-10 10:00:02 ERROR [svc] boom",
        "2024-01-10 10:00:03 WARN [svc] careful",
    ]
    analyzer.process_lines(lines)
    stats = analyzer.stats
    assert stats.lines_read == 9
    assert stats.blank_lines == 2
    assert stats.unparsed == 1
    assert stats.unparsed_samples == ["garbage that is not a log line"]
    assert stats.continuation_lines == 2
    assert stats.truncated_lines == 1
    assert stats.filtered["below_min_level"] == 1
    assert stats.analyzed == 3
    assert (stats.errors, stats.warnings) == (1, 1)
    assert stats.by_format["text"] == 4
    assert analyzer.watermark == analyzer.stats.last_ts


def test_window_scoped_result_and_service_status(config: AnalyzerConfig) -> None:
    lines = (FIXTURES / "scenario1_cascade.log").read_text().splitlines()
    full = analyze(lines, config)
    windowed = analyze(lines, config, window=10)
    assert full.window_events == 7
    assert windowed.window_events < full.window_events
    assert windowed.period_start == windowed.period_end - 10  # type: ignore[operator]
    statuses = {s.name: s.status for s in full.services}
    assert statuses["payment-service"] == "CRITICAL"
    payment = next(s for s in full.services if s.name == "payment-service")
    assert payment.error_rate == 100.0
    assert payment.trend_percent is not None
    assert payment.trend_percent > 0


def test_noise_reduction_definition() -> None:
    quiet = analyze(["2024-01-10 10:00:00 INFO [a] fine"], build_config())
    assert quiet.noise_reduction == 100.0
    assert quiet.alerts == []


def test_advance_clock_resolves_idle_incidents() -> None:
    analyzer = Analyzer(build_config(TOPOLOGY))
    events = analyzer.process_lines(
        ["2024-01-10 10:00:00 ERROR [order-service] java.lang.OutOfMemoryError"]
    )
    assert [e.kind for e in events] == [AlertEventKind.NEW]
    later = analyzer.advance_clock(analyzer.watermark + 120)  # type: ignore[operator]
    assert [e.kind for e in later] == [AlertEventKind.RESOLVED]
    assert Analyzer(build_config()).watermark is None


def test_plugin_detector_can_raise_alerts() -> None:
    config = build_config(
        {"detectors": {"plugins": ["tests.unit.plugin_examples:KeywordDetector"]}}
    )
    result = analyze(["2024-01-10 10:00:00 INFO [deploy] canary-failed on host-3"], config)
    assert len(result.alerts) == 1
    assert result.alerts[0].severity.name == "HIGH"


def test_disabling_detectors() -> None:
    config = build_config({"detectors": {"enabled": []}})
    lines = [f"2024-01-10 10:00:{i:02d} INFO [db] Connection pool: {90 + i}/100" for i in range(9)]
    assert analyze(lines, config).alerts == []


def test_peak_memory_is_reported() -> None:
    assert peak_memory_mb() > 0


# ------------------------------------------------------------------------------- output
def test_console_dashboard_has_the_spec_sections(config: AnalyzerConfig) -> None:
    result = analyze((FIXTURES / "scenario1_cascade.log").read_text().splitlines(), config)
    text = ConsoleRenderer(color=False).dashboard(result)
    for section in (
        "LOG ANALYSIS DASHBOARD",
        "Time Window: 2024-01-10 10:00:00 - 10:01:17",
        "Logs Processed:",
        "Errors Detected:",
        "Alerts Generated:",
        "Noise Reduction:",
        "ALERTS",
        "TREND ANALYSIS:",
        "Status",
    ):
        assert section in text
    assert "[CRITICAL] Database Connection Crisis" in text
    assert "Root Cause:" in text
    assert "↑" in text
    assert "\033[" not in text
    live = ConsoleRenderer(color=True).dashboard(result, live=True)
    assert "ACTIVE ALERTS:" in live
    assert "\033[1;31m" in live


def test_console_dashboard_without_events() -> None:
    result = analyze([], build_config())
    text = ConsoleRenderer(color=False, max_trend_rows=1).dashboard(result)
    assert "(no events)" in text
    assert "(none)" in text


def test_event_lines_and_json(config: AnalyzerConfig) -> None:
    analyzer = Analyzer(config)
    events = analyzer.process_lines((FIXTURES / "scenario1_cascade.log").read_text().splitlines())
    events += analyzer.advance_clock(analyzer.watermark + 3600)  # type: ignore[operator]
    renderer = ConsoleRenderer(color=False)
    rendered = [renderer.event(e) for e in events]
    assert rendered[0].startswith("[10:01:00] NEW")
    assert "root cause: database" in rendered[-2]
    assert "RESOLVED" in rendered[-1]
    assert "lasted" in rendered[-1]
    view = analyzer.correlator.builder.build(events[0].incident, events[0].assessment)
    payload = json.loads(event_json(events[0], view.to_dict()))
    assert payload["event"] == "NEW"
    assert payload["alert"]["alert_id"] == "ALR-20240110-001"


def test_json_report_shape(config: AnalyzerConfig) -> None:
    result = analyze((FIXTURES / "scenario3_dev_noise.log").read_text().splitlines(), config)
    report = report_dict(result)
    assert report["analysis_period"] == {
        "start": "2024-01-10T10:00:01Z",
        "end": "2024-01-10T10:00:06Z",
    }
    assert report["statistics"]["total_logs"] == 7
    assert report["statistics"]["logs_ignored"] == 3
    assert report["statistics"]["alerts_generated"] == 1
    assert report["services"][0]["name"] == "production-api"
    assert report["metrics"]["memory_usage_mb"] > 0
    assert json.loads(report_json(result, indent=None)) == json.loads(report_json(result))


def test_use_color(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    class Tty:
        def isatty(self) -> bool:
            return True

    monkeypatch.delenv("NO_COLOR", raising=False)
    assert use_color("auto", Tty())  # type: ignore[arg-type]
    assert use_color("always", object())  # type: ignore[arg-type]
    assert not use_color("never", Tty())  # type: ignore[arg-type]
    monkeypatch.setenv("NO_COLOR", "1")
    assert not use_color("auto", Tty())  # type: ignore[arg-type]


def test_silent_dependency_blamed_for_slowness_is_called_slow_not_down() -> None:
    # Only callers report the database, and only as slow: the alert must not say "down".
    lines = [
        f"2024-01-10 10:00:0{i} INFO [reports] Query took {1500 + 300 * i}ms" for i in range(3)
    ]
    (alert,) = analyze(lines, build_config({})).alerts
    view = alert.to_dict()
    assert view["root_cause_analysis"]["probable_cause"] == (
        "Slow database queries (inferred from slow calls reported by reports)"
    )
    assert "Unreachable" not in view["title"]
    assert "unavailable" not in view["summary"]
    assert any(
        "reported slow calls to database" in e for e in view["root_cause_analysis"]["evidence"]
    )


def test_silent_dependency_blamed_for_failures_is_called_unreachable() -> None:
    lines = [
        f"2024-01-10 10:00:0{i} ERROR [payment-service] Connection timeout to payment-provider"
        for i in range(3)
    ]
    (alert,) = analyze(lines, build_config(TOPOLOGY)).alerts
    view = alert.to_dict()
    assert view["title"].endswith("Payment Provider Unreachable")
    assert view["root_cause_analysis"]["probable_cause"].startswith("payment-provider unavailable")
    assert any(
        "failed calling payment-provider" in e for e in view["root_cause_analysis"]["evidence"]
    )
