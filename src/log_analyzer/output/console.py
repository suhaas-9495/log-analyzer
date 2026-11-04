"""Console rendering: the dashboard from the problem statement and live alert events."""

from __future__ import annotations

import os
import sys
from typing import TextIO

from log_analyzer.alerts.builder import AlertView
from log_analyzer.correlation.correlator import AlertEvent, AlertEventKind
from log_analyzer.engine import AnalysisResult
from log_analyzer.models import Severity
from log_analyzer.timeutil import format_clock, format_datetime, format_duration

_WIDTH = 79
_HEAVY = "═" * _WIDTH
_LIGHT = "─" * _WIDTH

_RESET = "\033[0m"
_SEVERITY_COLOR = {
    Severity.CRITICAL: "\033[1;31m",
    Severity.HIGH: "\033[31m",
    Severity.MEDIUM: "\033[33m",
    Severity.LOW: "\033[36m",
}
_STATUS_COLOR = {
    "CRITICAL": "\033[1;31m",
    "DEGRADED": "\033[31m",
    "WARNING": "\033[33m",
    "HEALTHY": "\033[32m",
}
_EVENT_LABEL = {
    AlertEventKind.NEW: "NEW     ",
    AlertEventKind.UPDATED: "UPDATED ",
    AlertEventKind.RESOLVED: "RESOLVED",
    AlertEventKind.REOPENED: "REOPENED",
    AlertEventKind.MERGED: "MERGED  ",
}


def use_color(mode: str, stream: TextIO) -> bool:
    """Honour ``--color``/config, ``NO_COLOR`` and whether the stream is a terminal."""
    if mode == "always":
        return True
    if mode == "never" or os.environ.get("NO_COLOR"):
        return False
    return hasattr(stream, "isatty") and stream.isatty()


class ConsoleRenderer:
    def __init__(self, *, color: bool, max_trend_rows: int = 15) -> None:
        self._color = color
        self._max_rows = max_trend_rows

    # ------------------------------------------------------------------ dashboard
    def dashboard(self, result: AnalysisResult, *, live: bool = False) -> str:
        lines = [_HEAVY, "LOG ANALYSIS DASHBOARD", _HEAVY]
        lines.append(f"Time Window: {self._period(result)}")
        lines.append(_LIGHT)
        stats = result.stats
        lines += [
            f"{'Logs Processed:':<24}{stats.lines_read - stats.blank_lines:,}",
            f"{'Errors Detected:':<24}{result.window_errors:,}",
            f"{'Alerts Generated:':<24}{len(result.alerts):,}",
            f"{'Noise Reduction:':<24}{result.noise_reduction:.1f}%",
        ]
        if stats.ignored:
            lines.append(f"{'Ignored (filters):':<24}{stats.ignored:,}")
        if stats.unparsed:
            lines.append(f"{'Unparseable lines:':<24}{stats.unparsed:,}")
        active = [a for a in result.alerts if a.status == "active"]
        shown = active if live else result.alerts
        heading = "ACTIVE ALERTS:" if live else f"ALERTS ({len(active)} active):"
        lines += ["", heading]
        if not shown:
            lines.append("  (none)")
        now = result.period_end or 0.0
        for alert in shown:
            lines += ["", *self._alert(alert, now)]
        lines += ["", "TREND ANALYSIS:", _LIGHT]
        lines.append(
            f"{'Service':<24} | {'Errors':>7} | {'Error rate':>10} | {'Trend':<10} | Status"
        )
        lines.append(_LIGHT)
        for svc in result.services[: self._max_rows]:
            trend = _trend(svc.trend_percent)
            status = self._paint(svc.status, _STATUS_COLOR.get(svc.status, ""))
            lines.append(
                f"{svc.name[:24]:<24} | {svc.errors:>7,} | {svc.error_rate:>9.2f}% | "
                f"{trend:<10} | {status}"
            )
        hidden = len(result.services) - self._max_rows
        if hidden > 0:
            lines.append(f"... {hidden} more services")
        lines += [_LIGHT, self._footer(result)]
        return "\n".join(lines)

    def _alert(self, alert: AlertView, now: float) -> list[str]:
        sev = self._paint(f"[{alert.severity.name}]", _SEVERITY_COLOR[alert.severity])
        out = [f"{sev} {alert.title}  ({alert.alert_id})"]
        started = f"{format_clock(alert.first_ts)} ({format_duration(now - alert.first_ts)} ago)"
        if alert.status == "resolved":
            started += f", resolved after {format_duration(alert.last_ts - alert.first_ts)}"
        out.append(f" • Started: {started}")
        out += [f" • {line}" for line in alert.highlights]
        return out

    def _period(self, result: AnalysisResult) -> str:
        if result.period_start is None or result.period_end is None:
            return "(no events)"
        span = format_duration(result.period_end - result.period_start)
        end = format_datetime(result.period_end)
        start = format_datetime(result.period_start)
        same_day = start[:10] == end[:10]
        return f"{start} - {end[11:] if same_day else end} ({span})"

    @staticmethod
    def _footer(result: AnalysisResult) -> str:
        lines = result.stats.lines_read
        rate = lines / result.processing_seconds if result.processing_seconds > 0 else 0.0
        return (
            f"Processed {lines:,} lines in {result.processing_seconds:.2f}s "
            f"({rate:,.0f} lines/s), peak memory {result.peak_memory_mb:.1f} MB"
        )

    # --------------------------------------------------------------------- events
    def event(self, event: AlertEvent) -> str:
        alert = event.incident.alert
        alert_id = alert.alert_id if alert else "?"
        a = event.assessment
        label = _EVENT_LABEL[event.kind]
        if event.kind is AlertEventKind.RESOLVED:
            duration = format_duration(event.incident.last_activity - event.incident.opened_at)
            return f"[{format_clock(event.ts)}] {label} {alert_id} {a.title} (lasted {duration})"
        if event.kind is AlertEventKind.MERGED:
            return (
                f"[{format_clock(event.ts)}] {label} {alert_id} {a.title} "
                "(re-classified as background noise)"
            )
        sev = self._paint(f"[{a.severity.name}]", _SEVERITY_COLOR[a.severity])
        root = f"root cause: {a.root.service} ({a.root.confidence:.0%})"
        return f"[{format_clock(event.ts)}] {label} {sev} {alert_id} {a.title} - {root}"

    def _paint(self, text: str, code: str) -> str:
        return f"{code}{text}{_RESET}" if self._color and code else text


def _trend(percent: float | None) -> str:
    if percent is None:
        return "-"
    if abs(percent) < 1:
        return "→ 0%"
    arrow = "↑" if percent > 0 else "↓"
    return f"{arrow} {abs(percent):,.0f}%"


def write(text: str, stream: TextIO | None = None) -> None:
    target = stream or sys.stdout
    target.write(text + "\n")
    target.flush()
