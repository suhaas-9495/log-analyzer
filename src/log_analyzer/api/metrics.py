"""Self-monitoring for the HTTP API: ``GET /metrics`` in the Prometheus text format.

"Alert on the alerter": an analyzer that silently stops receiving logs, slows down, or
fails to parse its input is itself an incident. The counters below are what an operator
would scrape and graph (for example in Grafana) and alert on:

* request rate and errors by route and status;
* analysis volume (lines received, log records analyzed, unparsed lines);
* alerts produced, by severity;
* analysis latency as a histogram (for p50/p95/p99 via ``histogram_quantile``).

The registry is tiny and dependency-free on purpose; with more metrics the
``prometheus_client`` library would be the natural replacement.
"""

from __future__ import annotations

import bisect
import threading
import time
from collections import Counter
from collections.abc import Mapping
from typing import Any

from log_analyzer import __version__

CONTENT_TYPE = "text/plain; version=0.0.4; charset=utf-8"

# Analysis latency buckets in seconds: a single request ranges from a few lines
# (milliseconds) to api.max_lines lines (seconds).
LATENCY_BUCKETS: tuple[float, ...] = (0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0)

_PREFIX = "log_analyzer"


class ServerMetrics:
    """Thread-safe counters for one API server process."""

    def __init__(self, routes: frozenset[str], clock: Any = time.time) -> None:
        self._routes = routes
        self._lock = threading.Lock()
        self._started = clock()
        self._requests: Counter[tuple[str, str, int]] = Counter()
        self._alerts: Counter[str] = Counter()
        self._lines = 0
        self._logs = 0
        self._unparsed = 0
        self._bucket_counts = [0] * len(LATENCY_BUCKETS)
        self._latency_sum = 0.0
        self._latency_count = 0

    def route(self, path: str) -> str:
        """Bound label cardinality: unknown paths are reported as ``other``."""
        return path if path in self._routes else "other"

    def observe_request(self, method: str, path: str, status: int) -> None:
        with self._lock:
            self._requests[(method, self.route(path), status)] += 1

    def observe_analysis(self, lines: int, report: Mapping[str, Any], seconds: float) -> None:
        stats = report["statistics"]
        with self._lock:
            self._lines += lines
            self._logs += int(stats["total_logs"])
            self._unparsed += int(stats.get("unparsed_lines", 0))
            for alert in report["alerts"]:
                self._alerts[str(alert["severity"])] += 1
            index = bisect.bisect_left(LATENCY_BUCKETS, seconds)
            if index < len(self._bucket_counts):
                self._bucket_counts[index] += 1
            self._latency_sum += seconds
            self._latency_count += 1

    def render(self) -> str:
        """The current values in the Prometheus text exposition format."""
        with self._lock:
            out: list[str] = []
            _family(out, "build_info", "gauge", "Analyzer version.")
            out.append(f'{_PREFIX}_build_info{{version="{__version__}"}} 1')
            _family(out, "start_time_seconds", "gauge", "Server start time (Unix seconds).")
            out.append(f"{_PREFIX}_start_time_seconds {self._started:.3f}")
            _family(out, "http_requests_total", "counter", "HTTP requests by route and status.")
            for (method, route, status), count in sorted(self._requests.items()):
                labels = f'method="{method}",route="{route}",status="{status}"'
                out.append(f"{_PREFIX}_http_requests_total{{{labels}}} {count}")
            _family(out, "lines_received_total", "counter", "Log lines received for analysis.")
            out.append(f"{_PREFIX}_lines_received_total {self._lines}")
            _family(out, "logs_analyzed_total", "counter", "Log records analyzed.")
            out.append(f"{_PREFIX}_logs_analyzed_total {self._logs}")
            _family(out, "unparsed_lines_total", "counter", "Lines in no known format.")
            out.append(f"{_PREFIX}_unparsed_lines_total {self._unparsed}")
            _family(out, "alerts_total", "counter", "Alerts produced, by severity.")
            for severity, count in sorted(self._alerts.items()):
                out.append(f'{_PREFIX}_alerts_total{{severity="{severity}"}} {count}')
            _family(out, "analysis_duration_seconds", "histogram", "Time to analyze one request.")
            cumulative = 0
            for bound, count in zip(LATENCY_BUCKETS, self._bucket_counts, strict=True):
                cumulative += count
                out.append(
                    f'{_PREFIX}_analysis_duration_seconds_bucket{{le="{bound:g}"}} {cumulative}'
                )
            out.append(
                f'{_PREFIX}_analysis_duration_seconds_bucket{{le="+Inf"}} {self._latency_count}'
            )
            out.append(f"{_PREFIX}_analysis_duration_seconds_sum {self._latency_sum:.6f}")
            out.append(f"{_PREFIX}_analysis_duration_seconds_count {self._latency_count}")
        return "\n".join(out) + "\n"


def _family(out: list[str], name: str, kind: str, help_text: str) -> None:
    out.append(f"# HELP {_PREFIX}_{name} {help_text}")
    out.append(f"# TYPE {_PREFIX}_{name} {kind}")
