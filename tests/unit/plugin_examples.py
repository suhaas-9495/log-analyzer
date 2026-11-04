"""Example plugins used by the tests (and as documentation of the plugin API)."""

from __future__ import annotations

from collections.abc import Sequence

from log_analyzer.config.schema import AnalyzerConfig, ParserConfig
from log_analyzer.models import Category, Level, LogEvent, Severity, Signal, SignalSource
from log_analyzer.processing.metrics import MetricSample

NOT_CALLABLE = 42


class PipeParser:
    """Parses ``<epoch>|<LEVEL>|<service>|<message>`` lines."""

    name = "pipe"

    def __init__(self, config: ParserConfig) -> None:
        self.config = config

    def parse(self, line: str, line_no: int) -> LogEvent | None:
        parts = line.split("|", 3)
        if len(parts) != 4 or not parts[0].isdigit():
            return None
        ts, level, service, message = parts
        return LogEvent(
            ts=float(ts),
            level=Level.parse(level),
            service=service,
            message=message,
            raw=line,
            fmt=self.name,
            line_no=line_no,
        )


class KeywordDetector:
    """Emits a HIGH signal for every line containing 'canary-failed'."""

    name = "keyword"

    def __init__(self, config: AnalyzerConfig) -> None:
        self.config = config

    def observe(self, event: LogEvent, samples: Sequence[MetricSample]) -> list[Signal]:
        del samples
        if "canary-failed" not in event.message:
            return []
        return [
            Signal(
                kind="canary",
                source=SignalSource.DETECTOR,
                ts=event.ts,
                service=event.service,
                severity=Severity.HIGH,
                category=Category.AVAILABILITY,
                fingerprint=("canary", event.service),
                template="canary failed",
                event=event,
            )
        ]
