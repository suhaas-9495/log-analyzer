"""Detector plugin interface.

A detector is a stateful consumer of events that emits *signals* when it observes an
anomaly that no single log line reveals on its own (rates, trends, saturation).
Detectors must keep their memory bounded: per-key state lives in an LRU capped by
``limits.max_tracked_keys`` and every per-key buffer has a fixed maximum length.
"""

from __future__ import annotations

from collections import OrderedDict
from collections.abc import Callable, Sequence
from typing import Any, Generic, Protocol, TypeVar

from log_analyzer.config.schema import AnalyzerConfig
from log_analyzer.models import LogEvent, Signal
from log_analyzer.plugins import Registry
from log_analyzer.processing.metrics import MetricSample


class Detector(Protocol):
    name: str

    def observe(self, event: LogEvent, samples: Sequence[MetricSample]) -> list[Signal]:
        """Consume one event (plus metrics extracted from it); return any new signals."""


DetectorFactory = Callable[[AnalyzerConfig], Detector]
DETECTORS: Registry[DetectorFactory] = Registry("detector")

K = TypeVar("K")
V = TypeVar("V")


class BoundedState(Generic[K, V]):
    """LRU map that evicts the least recently used key beyond ``capacity``."""

    def __init__(self, capacity: int, factory: Callable[[], V]) -> None:
        self._data: OrderedDict[K, V] = OrderedDict()
        self._capacity = capacity
        self._factory = factory
        self.evictions = 0

    def get(self, key: K) -> V:
        value = self._data.get(key)
        if value is None:
            value = self._factory()
            self._data[key] = value
            if len(self._data) > self._capacity:
                self._data.popitem(last=False)
                self.evictions += 1
        else:
            self._data.move_to_end(key)
        return value

    def peek(self, key: K) -> V | None:
        return self._data.get(key)

    def items(self) -> list[tuple[K, V]]:
        return list(self._data.items())

    def __len__(self) -> int:
        return len(self._data)


def describe(detector: Any) -> str:
    return getattr(detector, "name", type(detector).__name__)
