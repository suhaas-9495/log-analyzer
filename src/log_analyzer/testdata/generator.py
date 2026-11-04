"""Deterministic generator of realistic, multi-format test logs with injected incidents.

Mirrors the structure of the provided sample data: ~70% normal traffic in three formats,
plus (optionally) a gradual performance degradation, a database connection-pool
exhaustion cascade, a payment-provider outage cascade, bands of random heterogeneous
errors, and development/debug noise. A small fraction of numeric fields is deliberately
garbled (``Request processed in ord_123ms``), as in the sample data.

Used by the integration tests, the Scenario 4 performance test and ``make bench``.
"""

from __future__ import annotations

import json
import random
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import TextIO

SCENARIOS = (
    "perf_degradation",
    "db_pool_exhaustion",
    "payment_cascade",
    "random_errors",
    "dev_noise",
)

SERVICES = (
    "api-gateway",
    "auth-service",
    "user-service",
    "order-service",
    "payment-service",
    "inventory-service",
    "search-service",
    "recommendation-service",
    "notification-service",
    "analytics-service",
)
DEV_SERVICES = ("dev-server", "localhost", "test-runner", "debug-console")
_DB_CLIENTS = ("order-service", "inventory-service", "payment-service", "user-service")
_GARBLE_RATE = 0.02
_NORMAL_LINES_PER_SECOND = 15.0

_NORMAL_MESSAGES: tuple[Callable[[random.Random], str], ...] = (
    lambda r: f"Request processed in {r.randint(10, 200)}ms",
    lambda r: f"Search query executed in {r.randint(10, 200)}ms",
    lambda r: "User profile updated",
    lambda r: f"Cache hit for key key_{r.getrandbits(32):08x}",
    lambda r: f"Order ord_{r.randint(10000, 99999)} processed successfully",
    lambda r: f"Payment processed for amount ${r.uniform(5, 999):.2f}",
    lambda r: f"Session created for user usr_{r.randint(1000, 9999)}",
    lambda r: "Connected to upstream service",
    lambda r: "Health check passed",
    lambda r: "Configuration reloaded",
    lambda r: f"Background job completed in {r.randint(10, 200)}ms",
)
_RANDOM_ERRORS: tuple[Callable[[random.Random, str], str], ...] = (
    lambda r, t: "Too many connections",
    lambda r, t: "Deadlock detected",
    lambda r, t: "Invalid request format",
    lambda r, t: f"Permission denied for resource {t}",
    lambda r, t: f"Upstream service {t} not responding",
    lambda r, t: f"Connection timeout to {t} after {r.randint(70, 5000)}ms",
    lambda r, t: f"Failed to connect to {t}: timeout",
    lambda r, t: f"Request took {r.randint(70, 5000)}ms to complete",
    lambda r, t: f"Slow query detected: {r.randint(70, 5000)}ms",
    lambda r, t: f"High memory usage detected: {r.randint(70, 99)}%",
    lambda r, t: f"Null pointer exception in {t}",
    lambda r, t: f"File not found: {t}",
    lambda r, t: f"Authentication failed for user {t}",
    lambda r, t: f"Rate limit exceeded for client {t}",
    lambda r, t: "Transaction rolled back",
    lambda r, t: "Connection pool exhausted",
)
_DEV_MESSAGES = (
    "Starting hot reload",
    "Webpack compilation complete",
    "Test endpoint called",
    "Debug mode enabled",
    "Mock data generated",
    "Watching for file changes",
    "Development server started on port 3000",
    "Console.log: TODO - fix this later",
)


@dataclass(frozen=True, slots=True)
class GeneratorSettings:
    lines: int = 10_000
    seed: int = 42
    start: str = "2025-10-07T14:00:00"
    scenarios: tuple[str, ...] = SCENARIOS


class _Writer:
    """Formats records in one of the three supported formats, tracking the clock."""

    def __init__(self, rng: random.Random, start: datetime, out: TextIO) -> None:
        self.rng = rng
        self.now = start
        self.out = out
        self.count = 0

    def advance(self, seconds: float) -> None:
        self.now += timedelta(seconds=seconds)

    def emit(
        self,
        level: str,
        service: str,
        message: str,
        *,
        fmt: str | None = None,
        extra: dict[str, object] | None = None,
    ) -> None:
        fmt = fmt or self.rng.choice(("text", "text", "json", "app"))
        rid = f"req-{self.rng.getrandbits(48):012x}"
        if fmt == "json" or extra:
            record: dict[str, object] = {
                "timestamp": self.now.strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
                "level": level,
                "service": service,
                "message": message,
                "request_id": rid,
            }
            record.update(extra or {})
            line = json.dumps(record)
        elif fmt == "app":
            line = f"[{self.now:%Y-%m-%d %H:%M:%S}] production.{level}: {message}"
        else:
            stamp = self.now.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
            line = f"{stamp} {level:<5} [{service}] RequestID:{rid} {message}"
        self.out.write(line + "\n")
        self.count += 1


def generate(settings: GeneratorSettings, out: TextIO) -> int:
    """Write roughly ``settings.lines`` lines to ``out``; returns the exact count."""
    rng = random.Random(settings.seed)  # noqa: S311 - test data, not cryptography
    start = datetime.fromisoformat(settings.start)
    if start.tzinfo is None:
        start = start.replace(tzinfo=UTC)
    w = _Writer(rng, start, out)
    plan = _plan(settings)
    incident_budget = sum(size for name, size in plan if name != "normal")
    normal_total = max(0, settings.lines - incident_budget)
    normal_blocks = sum(1 for name, _ in plan if name == "normal")
    for name, size in plan:
        if name == "normal":
            _normal(w, normal_total // max(1, normal_blocks))
        else:
            _BLOCKS[name](w, size)
    return w.count


def _plan(settings: GeneratorSettings) -> list[tuple[str, int]]:
    n = settings.lines
    wanted = set(settings.scenarios)
    plan: list[tuple[str, int]] = [("normal", 0)]
    steps = [
        ("dev_noise", max(20, n // 50)),
        ("perf_degradation", 80),
        ("random_errors", max(30, n // 33)),
        ("db_pool_exhaustion", 140),
        ("payment_cascade", 90),
        ("random_errors", max(30, n // 33)),
        ("dev_noise", max(10, n // 100)),
    ]
    for name, size in steps:
        if name in wanted:
            plan.append((name, size))
            plan.append(("normal", 0))
    return plan


def _garble(rng: random.Random, value: str) -> str:
    if rng.random() < _GARBLE_RATE:
        return f"{rng.choice(('ord', 'usr', 'prod', 'key'))}_{rng.randint(10, 99999)}"
    return value


def _normal(w: _Writer, count: int) -> None:
    for _ in range(count):
        w.advance(w.rng.expovariate(_NORMAL_LINES_PER_SECOND))
        message = w.rng.choice(_NORMAL_MESSAGES)(w.rng)
        if "ms" in message and w.rng.random() < _GARBLE_RATE:
            message = message.rsplit(" ", 1)[0] + f" {_garble(w.rng, 'x')}ms"
        w.emit("INFO", w.rng.choice(SERVICES), message)


def _dev_noise(w: _Writer, count: int) -> None:
    for _ in range(count):
        w.advance(w.rng.uniform(0.1, 0.5))
        w.emit("DEBUG", w.rng.choice(DEV_SERVICES), w.rng.choice(_DEV_MESSAGES), fmt="text")


def _perf_degradation(w: _Writer, count: int) -> None:
    """Latency climbs steadily (230ms -> 450ms) without ever crossing 1000ms."""
    for i in range(count):
        w.advance(0.7)
        progress = i / max(1, count - 1)
        if i % 4 == 0:
            ms = int(60 + 250 * progress + w.rng.uniform(-15, 15))
            w.emit(
                "WARN",
                "database",
                "Slow query detected",
                fmt="json",
                extra={
                    "query": "SELECT * FROM orders WHERE ...",
                    "execution_time_ms": ms,
                    "rows_examined": w.rng.randint(10_000, 99_999),
                },
            )
        else:
            ms = int(230 + 220 * progress + w.rng.uniform(-20, 20))
            service = w.rng.choice(("api-gateway", "order-service", "search-service"))
            w.emit("WARN", service, f"Request processed in {ms}ms", fmt="text")


def _random_errors(w: _Writer, count: int) -> None:
    for _ in range(count):
        w.advance(w.rng.uniform(1.0, 5.0))
        target = w.rng.choice(
            (
                *SERVICES,
                str(w.rng.randint(1, 5000)),
                f"resource_{w.rng.randint(1, 99)}",
                f"file_{w.rng.getrandbits(32):08x}.txt",
            )
        )
        message = w.rng.choice(_RANDOM_ERRORS)(w.rng, target)
        level = w.rng.choice(("WARN", "ERROR"))
        w.emit(level, w.rng.choice(SERVICES), message, fmt=w.rng.choice(("text", "json")))


def _db_pool_exhaustion(w: _Writer, count: int) -> None:
    """Pool fills, nearly exhausts, exhausts; DB clients and the gateway then fail."""
    for active in range(50, 90, 2):
        w.advance(6.0)
        w.emit(
            "INFO",
            "database",
            "Connection pool status",
            fmt="json",
            extra={"active_connections": active, "max_connections": 100, "available": 100 - active},
        )
    for waiting, active in enumerate(range(90, 100, 2)):
        w.advance(2.0)
        w.emit(
            "WARN",
            "database",
            "Connection pool nearly exhausted",
            fmt="json",
            extra={
                "active_connections": active,
                "max_connections": 100,
                "waiting_threads": waiting * 3,
            },
        )
    w.advance(2.0)
    w.emit(
        "ERROR",
        "database",
        "Connection pool exhausted",
        fmt="json",
        extra={
            "active_connections": 100,
            "max_connections": 100,
            "waiting_threads": 15,
            "rejected_connections": 1,
        },
    )
    remaining = max(10, count - 26)
    for i in range(remaining):
        client = w.rng.choice(_DB_CLIENTS)
        if i % 3 == 2:
            w.advance(w.rng.uniform(25.0, 30.0))
            w.emit(
                "ERROR", "api-gateway", f"Connection timeout to {client} after 30000ms", fmt="text"
            )
        else:
            w.advance(w.rng.uniform(0.1, 0.5))
            w.emit(
                "ERROR", client, "Failed to acquire database connection: pool exhausted", fmt="text"
            )


def _payment_cascade(w: _Writer, count: int) -> None:
    """Third-party payment provider goes down; failures ripple up the call chain."""
    w.emit(
        "ERROR", "payment-provider", "Service health check failed: Connection refused", fmt="text"
    )
    rounds = max(3, count // 9)
    for _ in range(rounds):
        w.advance(1.5)
        w.emit(
            "ERROR",
            "payment-service",
            "Payment provider unavailable: connection refused",
            fmt="text",
        )
        for attempt in range(1, 4):
            w.advance(0.12)
            w.emit(
                "WARN",
                "payment-service",
                f"Retry attempt {attempt}/3 for payment provider",
                fmt="text",
            )
    for i in range(rounds * 2):
        w.advance(0.4)
        if i % 3 == 0:
            w.emit(
                "ERROR",
                "order-service",
                "Cannot process order: payment service unavailable",
                fmt="text",
            )
        elif i % 3 == 1:
            w.emit(
                "ERROR",
                "api-gateway",
                "Order processing failed: downstream service error",
                fmt="text",
            )
        else:
            order = json.dumps(
                {
                    "order_id": f"ord_{w.rng.randint(10000, 99999)}",
                    "error": "Payment processing unavailable",
                }
            )
            w.emit("ERROR", "web-app", f"Customer order failed {order}", fmt="app")


_BLOCKS: dict[str, Callable[[_Writer, int], None]] = {
    "dev_noise": _dev_noise,
    "perf_degradation": _perf_degradation,
    "random_errors": _random_errors,
    "db_pool_exhaustion": _db_pool_exhaustion,
    "payment_cascade": _payment_cascade,
}


def iter_lines(settings: GeneratorSettings) -> Iterator[str]:
    """Convenience for tests: generate into memory and iterate lines."""
    import io  # noqa: PLC0415

    buffer = io.StringIO()
    generate(settings, buffer)
    yield from buffer.getvalue().splitlines()
