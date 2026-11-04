"""Noise filters applied before any analysis (spec: "Ignore rules (reduce noise)")."""

from __future__ import annotations

import enum

from log_analyzer.config.schema import FilterConfig
from log_analyzer.models import LogEvent


class FilterReason(enum.StrEnum):
    LEVEL = "below_min_level"
    SERVICE = "ignored_service"
    PATTERN = "ignore_pattern"


class EventFilter:
    def __init__(self, config: FilterConfig) -> None:
        self._min_level = config.min_level
        self._service_regex = config.ignore_service_regex
        self._pattern_regexes = config.ignore_regexes

    def reason(self, event: LogEvent) -> FilterReason | None:
        """Why ``event`` should be dropped, or ``None`` to keep it."""
        if event.level < self._min_level:
            return FilterReason.LEVEL
        if self._service_regex is not None and self._service_regex.match(event.service):
            return FilterReason.SERVICE
        raw = event.raw
        for regex in self._pattern_regexes:
            if regex.search(raw):
                return FilterReason.PATTERN
        return None
