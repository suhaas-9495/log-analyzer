"""Shared fixtures and helpers for the test suite."""

from __future__ import annotations

import zipfile
from collections.abc import Callable, Iterable
from pathlib import Path
from typing import Any

import pytest

from log_analyzer.config import AnalyzerConfig, build_config, load_config
from log_analyzer.engine import AnalysisResult, Analyzer
from log_analyzer.models import Level, LogEvent

ROOT = Path(__file__).resolve().parents[1]
CONFIG_PATH = ROOT / "configs" / "config.yaml"
SAMPLE_10K = ROOT / "data" / "sample" / "test_logs.txt"
SAMPLE_100K_ZIP = ROOT / "data" / "sample" / "large_test_logs.txt.zip"
FIXTURES = ROOT / "tests" / "fixtures"

# A small topology used by unit tests that need service awareness.
TOPOLOGY: dict[str, Any] = {
    "services": [
        {
            "name": "api-gateway",
            "critical": True,
            "dependencies": ["order-service", "payment-service", "inventory-service"],
        },
        {"name": "web-app", "dependencies": ["api-gateway", "payment-service"]},
        {
            "name": "order-service",
            "dependencies": ["database", "payment-service"],
            "aliases": ["order"],
        },
        {
            "name": "payment-service",
            "critical": True,
            "dependencies": ["database", "payment-provider"],
            "aliases": ["payment"],
            "expected_error_rate": 0.05,
        },
        {"name": "inventory-service", "dependencies": ["database"]},
        {"name": "payment-provider", "aliases": ["payment provider"]},
        {"name": "database", "critical": True, "aliases": ["db"]},
    ],
}


@pytest.fixture(scope="session")
def config() -> AnalyzerConfig:
    """The repository's main configuration (configs/config.yaml)."""
    return load_config(CONFIG_PATH)


@pytest.fixture(scope="session")
def topology_config() -> AnalyzerConfig:
    return build_config(TOPOLOGY)


@pytest.fixture(scope="session")
def large_sample(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """The provided 100k-line sample, unzipped once per session."""
    target = tmp_path_factory.mktemp("sample")
    with zipfile.ZipFile(SAMPLE_100K_ZIP) as archive:
        archive.extract("large_test_logs.txt", target)
    return target / "large_test_logs.txt"


def analyze(
    lines: Iterable[str], cfg: AnalyzerConfig, window: float | None = None
) -> AnalysisResult:
    analyzer = Analyzer(cfg)
    for line in lines:
        analyzer.process_line(line)
    return analyzer.result(window)


def analyze_file(path: Path, cfg: AnalyzerConfig) -> AnalysisResult:
    with path.open(encoding="utf-8") as handle:
        return analyze(handle, cfg)


def event(
    message: str = "hello",
    *,
    service: str = "svc",
    level: Level = Level.ERROR,
    ts: float = 1_700_000_000.0,
    fields: dict[str, Any] | None = None,
    request_id: str | None = None,
) -> LogEvent:
    return LogEvent(
        ts=ts,
        level=level,
        service=service,
        message=message,
        raw=f"{level.name} [{service}] {message}",
        fmt="test",
        request_id=request_id,
        fields=fields or {},
    )


EventFactory = Callable[..., LogEvent]


@pytest.fixture
def make_event() -> EventFactory:
    return event
