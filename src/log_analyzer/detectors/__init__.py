"""Stateful anomaly detectors. Importing this package registers the built-ins."""

from log_analyzer.detectors import error_rate, latency, saturation
from log_analyzer.detectors.base import DETECTORS, Detector

__all__ = ["DETECTORS", "Detector", "error_rate", "latency", "saturation"]
