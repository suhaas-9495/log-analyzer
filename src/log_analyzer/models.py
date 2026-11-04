"""Core domain types shared by every stage of the pipeline.

The pipeline is::

    raw line -> LogEvent -> Signal(s) -> Incident -> Alert

* :class:`LogEvent` is a normalised log record, independent of the source format.
* :class:`Signal` is one *interpretation* of something noteworthy: a log line that
  matched a pattern rule, or a detector observation such as "error rate tripled".
* Incidents group related signals (see :mod:`log_analyzer.correlation`).
"""

from __future__ import annotations

import enum
from dataclasses import dataclass, field
from typing import Any


class Level(enum.IntEnum):
    """Normalised log level. Ordering allows ``level >= Level.WARN`` comparisons."""

    DEBUG = 10
    INFO = 20
    WARN = 30
    ERROR = 40
    CRITICAL = 50

    @classmethod
    def parse(cls, raw: str) -> Level:
        """Map the many spellings seen in the wild onto the five canonical levels.

        Raises:
            ValueError: if ``raw`` is not a recognised level name.
        """
        try:
            return _LEVEL_ALIASES[raw.strip().upper()]
        except KeyError:
            raise ValueError(f"unknown log level: {raw!r}") from None


_LEVEL_ALIASES: dict[str, Level] = {
    "TRACE": Level.DEBUG,
    "DEBUG": Level.DEBUG,
    "DBG": Level.DEBUG,
    "INFO": Level.INFO,
    "INFORMATION": Level.INFO,
    "NOTICE": Level.INFO,
    "WARN": Level.WARN,
    "WARNING": Level.WARN,
    "ERROR": Level.ERROR,
    "ERR": Level.ERROR,
    "SEVERE": Level.ERROR,
    "CRITICAL": Level.CRITICAL,
    "CRIT": Level.CRITICAL,
    "FATAL": Level.CRITICAL,
    "ALERT": Level.CRITICAL,
    "EMERGENCY": Level.CRITICAL,
    "EMERG": Level.CRITICAL,
}


class Severity(enum.IntEnum):
    """Alert severity, ordered so that ``max()`` picks the most severe."""

    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @classmethod
    def parse(cls, raw: str) -> Severity:
        try:
            return cls[raw.strip().upper()]
        except KeyError:
            allowed = ", ".join(s.name for s in cls)
            raise ValueError(f"unknown severity {raw!r} (expected one of: {allowed})") from None


class Category(enum.StrEnum):
    """What *kind* of problem a signal describes. Drives correlation and RCA.

    * ``dependency``   - a call to another component failed (timeout, refused, unavailable)
    * ``resource``     - a finite resource is exhausted (pools, memory, connections)
    * ``availability`` - the component itself is down / unhealthy
    * ``performance``  - the component is slow
    * ``application``  - a local bug or bad input; does not propagate
    * ``security``     - authn/authz failures
    """

    DEPENDENCY = "dependency"
    RESOURCE = "resource"
    AVAILABILITY = "availability"
    PERFORMANCE = "performance"
    APPLICATION = "application"
    SECURITY = "security"

    @classmethod
    def parse(cls, raw: str) -> Category:
        try:
            return cls(raw.strip().lower())
        except ValueError:
            allowed = ", ".join(c.value for c in cls)
            raise ValueError(f"unknown category {raw!r} (expected one of: {allowed})") from None


#: Categories that mean "this component is failing", as opposed to slow or buggy.
FAILURE_CATEGORIES = frozenset({Category.DEPENDENCY, Category.RESOURCE, Category.AVAILABILITY})


class SignalSource(enum.StrEnum):
    """Where a signal came from. Detector signals are pre-aggregated and trusted more."""

    PATTERN = "pattern"  # a single log line matched a configured pattern rule
    GENERIC = "generic"  # an ERROR line that matched no rule (grouped by message template)
    DETECTOR = "detector"  # a stateful detector (error rate, latency trend, saturation)


@dataclass(slots=True)
class LogEvent:
    """A parsed, format-independent log record."""

    ts: float  # event time, epoch seconds (UTC)
    level: Level
    service: str
    message: str
    raw: str
    fmt: str  # name of the parser that produced it
    request_id: str | None = None
    fields: dict[str, Any] = field(default_factory=dict)
    line_no: int = 0

    @property
    def is_error(self) -> bool:
        return self.level >= Level.ERROR


@dataclass(slots=True)
class Signal:
    """Something noteworthy, ready to be correlated into an incident."""

    kind: str  # pattern name or detector name
    source: SignalSource
    ts: float
    service: str
    severity: Severity
    category: Category
    fingerprint: tuple[str, ...]  # stable de-duplication key
    template: str  # normalised description used for "unique errors"
    event: LogEvent | None = None
    targets: frozenset[str] = frozenset()  # services this signal implicates as dependencies
    effective_ts: float | None = None  # when the failure began (timeouts start earlier)
    attributes: dict[str, Any] = field(default_factory=dict)
    min_occurrences: int | None = None  # per-rule override of the global gating threshold
    title: str | None = None
    probable_cause: str | None = None
    actions: tuple[str, ...] = ()

    @property
    def start_ts(self) -> float:
        return self.effective_ts if self.effective_ts is not None else self.ts

    @property
    def is_failure(self) -> bool:
        """A failure signal means the emitting service is (or is seeing) a hard failure."""
        if self.category not in FAILURE_CATEGORIES:
            return False
        if self.source is SignalSource.DETECTOR:
            return True
        return self.event is not None and self.event.level >= Level.WARN

    @property
    def is_weak(self) -> bool:
        """Weak signals carry no dependency evidence of their own (absorbed, never linked)."""
        return self.source is SignalSource.GENERIC or self.kind == "error_rate_spike"
