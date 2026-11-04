"""JSON report (spec: "JSON Output (optional, for integration)") and JSON-lines events."""

from __future__ import annotations

import json
from dataclasses import asdict
from typing import Any

from log_analyzer import __version__
from log_analyzer.correlation.correlator import AlertEvent
from log_analyzer.engine import AnalysisResult
from log_analyzer.timeutil import format_iso


def report_dict(result: AnalysisResult) -> dict[str, Any]:
    stats = result.stats
    lines_per_second = (
        stats.lines_read / result.processing_seconds if result.processing_seconds > 0 else 0.0
    )
    return {
        "analysis_period": {
            "start": format_iso(result.period_start) if result.period_start else None,
            "end": format_iso(result.period_end) if result.period_end else None,
        },
        "statistics": {
            "total_logs": stats.lines_read - stats.blank_lines,
            "errors_found": result.window_errors,
            "alerts_generated": len(result.alerts),
            "noise_reduction_percent": result.noise_reduction,
            # ---- extensions ----
            "warnings_found": stats.warnings,
            "logs_parsed": stats.parsed,
            "logs_analyzed": stats.analyzed,
            "logs_ignored": stats.ignored,
            "ignored_by_reason": dict(stats.filtered),
            "unparsed_lines": stats.unparsed,
            "continuation_lines": stats.continuation_lines,
            "formats": dict(stats.by_format),
            "active_alerts": sum(1 for a in result.alerts if a.status == "active"),
            "incidents": asdict(result.correlation),
        },
        "alerts": [alert.to_dict() for alert in result.alerts],
        "services": [
            {
                "name": svc.name,
                "events": svc.events,
                "errors": svc.errors,
                "warnings": svc.warnings,
                "error_rate_percent": round(svc.error_rate, 3),
                "expected_error_rate_percent": svc.expected_rate,
                "trend_percent": round(svc.trend_percent, 1)
                if svc.trend_percent is not None
                else None,
                "status": svc.status,
            }
            for svc in result.services
        ],
        "metrics": {
            "processing_time_ms": round(result.processing_seconds * 1000),
            "memory_usage_mb": result.peak_memory_mb,
            "lines_per_second": round(lines_per_second),
        },
        "analyzer_version": __version__,
    }


def report_json(result: AnalysisResult, *, indent: int | None = 2) -> str:
    return json.dumps(report_dict(result), indent=indent, ensure_ascii=False)


def event_json(event: AlertEvent, builder_view: dict[str, Any]) -> str:
    return json.dumps(
        {"event": event.kind.value, "at": format_iso(event.ts), "alert": builder_view},
        ensure_ascii=False,
    )
