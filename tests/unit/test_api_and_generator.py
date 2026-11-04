from __future__ import annotations

import http.client
import io
import json
import threading
from collections.abc import Iterator
from http import HTTPStatus
from typing import Any

import pytest

from log_analyzer.api.metrics import CONTENT_TYPE, LATENCY_BUCKETS, ServerMetrics
from log_analyzer.api.server import ROUTES, ApiError, analyze_payload, create_server
from log_analyzer.config import AnalyzerConfig, build_config
from log_analyzer.testdata.generator import SCENARIOS, GeneratorSettings, generate, iter_lines
from tests.conftest import FIXTURES

SCENARIO1 = (FIXTURES / "scenario1_cascade.log").read_text().splitlines()


# ------------------------------------------------------------------------- payload logic
def test_analyze_payload(config: AnalyzerConfig) -> None:
    report = analyze_payload(config, {"logs": SCENARIO1, "window": "5m"})
    assert report["statistics"]["alerts_generated"] == 1
    assert report["alerts"][0]["severity"] == "CRITICAL"


@pytest.mark.parametrize(
    ("payload", "status"),
    [
        ([], HTTPStatus.BAD_REQUEST),
        ({"logs": "one line"}, HTTPStatus.BAD_REQUEST),
        ({"logs": [1, 2]}, HTTPStatus.BAD_REQUEST),
        ({"logs": [], "extra": 1}, HTTPStatus.BAD_REQUEST),
        ({"logs": [], "window": "soon"}, HTTPStatus.BAD_REQUEST),
        ({"logs": [], "window": 5}, None),
        ({"logs": ["x"] * 3}, HTTPStatus.REQUEST_ENTITY_TOO_LARGE),
    ],
)
def test_payload_validation(payload: Any, status: HTTPStatus | None) -> None:
    config = build_config({"api": {"max_lines": 2}})
    if status is None:
        analyze_payload(config, payload)
        return
    with pytest.raises(ApiError) as info:
        analyze_payload(config, payload)
    assert info.value.status is status


# --------------------------------------------------------------------------- HTTP server
@pytest.fixture
def server(config: AnalyzerConfig) -> Iterator[tuple[str, int]]:
    small = build_config({"api": {"max_body_bytes": 4096, "port": 0}})
    srv = create_server(small, host="127.0.0.1")
    thread = threading.Thread(target=srv.serve_forever, daemon=True)
    thread.start()
    host, port = srv.server_address[:2]
    yield str(host), int(port)
    srv.shutdown()
    srv.server_close()
    del config


def request(
    target: tuple[str, int],
    method: str,
    path: str,
    body: bytes | None = None,
    headers: dict[str, str] | None = None,
) -> tuple[int, dict[str, Any]]:
    conn = http.client.HTTPConnection(*target, timeout=10)
    conn.request(method, path, body=body, headers=headers or {})
    response = conn.getresponse()
    payload = json.loads(response.read() or b"{}")
    conn.close()
    return response.status, payload


def test_http_analyze_and_health(server: tuple[str, int]) -> None:
    body = json.dumps({"logs": SCENARIO1, "window": "5m"}).encode()
    status, payload = request(
        server, "POST", "/analyze", body, {"Content-Type": "application/json"}
    )
    assert status == 200
    assert payload["statistics"]["alerts_generated"] == 1
    assert payload["alerts"][0]["root_cause_service"] == "database"
    status, payload = request(server, "GET", "/health")
    assert (status, payload["status"]) == (200, "ok")


@pytest.mark.parametrize(
    ("method", "path", "body", "headers", "status"),
    [
        ("GET", "/nope", None, None, 404),
        ("POST", "/nope", b"{}", None, 404),
        ("GET", "/analyze", None, None, 405),
        ("POST", "/analyze", b"{not json", None, 400),
        ("POST", "/analyze", b"\xff\xfe", None, 400),
        ("POST", "/analyze", b'{"logs": "x"}', None, 400),
        ("POST", "/analyze", b"x" * 5000, None, 413),
        ("POST", "/analyze", b"{}", {"Content-Length": "abc"}, 400),
    ],
)
def test_http_errors(
    server: tuple[str, int],
    method: str,
    path: str,
    body: bytes | None,
    headers: dict[str, str] | None,
    status: int,
) -> None:
    code, payload = request(server, method, path, body, headers)
    assert code == status
    assert payload["status"] == status


def test_http_requires_content_length(server: tuple[str, int]) -> None:
    conn = http.client.HTTPConnection(*server, timeout=10)
    conn.putrequest("POST", "/analyze")
    conn.endheaders()
    response = conn.getresponse()
    assert response.status == 411
    conn.close()


def test_error_responses_close_the_connection(server: tuple[str, int]) -> None:
    # A rejected body is never read; keeping the socket open would parse it as a request.
    conn = http.client.HTTPConnection(*server, timeout=10)
    conn.request("POST", "/analyze", body=b"x" * 5000)
    response = conn.getresponse()
    response.read()
    assert (response.status, response.getheader("Connection")) == (413, "close")
    conn.close()


def get_text(target: tuple[str, int], path: str) -> tuple[int, str, str]:
    conn = http.client.HTTPConnection(*target, timeout=10)
    conn.request("GET", path)
    response = conn.getresponse()
    text = response.read().decode()
    conn.close()
    return response.status, response.getheader("Content-Type") or "", text


def metric(text: str, sample: str) -> float:
    """Value of one exposition line, e.g. ``log_analyzer_alerts_total{severity="CRITICAL"}``."""
    for line in text.splitlines():
        if line.startswith(sample + " "):
            return float(line.rsplit(" ", 1)[1])
    raise AssertionError(f"{sample} not in /metrics output")


def test_metrics_endpoint_counts_requests_and_analyses(server: tuple[str, int]) -> None:
    body = json.dumps({"logs": [*SCENARIO1, "", "not a log line"]}).encode()
    assert request(server, "POST", "/analyze", body)[0] == 200
    assert request(server, "GET", "/nope")[0] == 404
    status, content_type, text = get_text(server, "/metrics?debug=1")
    assert status == 200
    assert content_type == CONTENT_TYPE
    p = "log_analyzer_"
    assert (
        metric(text, f'{p}http_requests_total{{method="POST",route="/analyze",status="200"}}') == 1
    )
    assert metric(text, f'{p}http_requests_total{{method="GET",route="other",status="404"}}') == 1
    assert metric(text, f"{p}lines_received_total") == len(SCENARIO1) + 2
    assert metric(text, f"{p}logs_analyzed_total") == len(SCENARIO1) + 1  # blank line skipped
    assert metric(text, f"{p}unparsed_lines_total") == 1
    assert metric(text, f'{p}alerts_total{{severity="CRITICAL"}}') == 1
    assert metric(text, f'{p}analysis_duration_seconds_bucket{{le="+Inf"}}') == 1
    assert metric(text, f"{p}analysis_duration_seconds_count") == 1
    assert "# TYPE log_analyzer_analysis_duration_seconds histogram" in text
    assert 'log_analyzer_build_info{version="' in text


def test_metrics_endpoint_can_be_disabled() -> None:
    cfg = build_config({"api": {"port": 0, "metrics_enabled": False}})
    srv = create_server(cfg, host="127.0.0.1")
    thread = threading.Thread(target=srv.serve_forever, daemon=True)
    thread.start()
    try:
        host, port = srv.server_address[:2]
        assert get_text((str(host), int(port)), "/metrics")[0] == 404
    finally:
        srv.shutdown()
        srv.server_close()


def test_latency_histogram_is_cumulative() -> None:
    m = ServerMetrics(ROUTES, clock=lambda: 1_700_000_000.0)
    report = {"statistics": {"total_logs": 1}, "alerts": []}
    for seconds in (0.001, 0.3, 0.3, 99.0):  # the last one is above every bucket
        m.observe_analysis(1, report, seconds)
    text = m.render()
    assert metric(text, 'log_analyzer_analysis_duration_seconds_bucket{le="0.005"}') == 1
    assert metric(text, 'log_analyzer_analysis_duration_seconds_bucket{le="0.5"}') == 3
    last = f'log_analyzer_analysis_duration_seconds_bucket{{le="{LATENCY_BUCKETS[-1]:g}"}}'
    assert metric(text, last) == 3
    assert metric(text, 'log_analyzer_analysis_duration_seconds_bucket{le="+Inf"}') == 4
    assert metric(text, "log_analyzer_analysis_duration_seconds_sum") == pytest.approx(99.601)
    assert metric(text, "log_analyzer_start_time_seconds") == 1_700_000_000.0


# ---------------------------------------------------------------------------- generator
def test_generator_is_deterministic_and_complete() -> None:
    settings = GeneratorSettings(lines=3000, seed=11)
    first, second = io.StringIO(), io.StringIO()
    count = generate(settings, first)
    generate(settings, second)
    assert first.getvalue() == second.getvalue()
    text = first.getvalue()
    assert abs(count - 3000) < 150
    for marker in (
        "Connection pool exhausted",
        "Service health check failed",
        "Slow query detected",
        "Starting hot reload",
        "production.",
        '"level"',
    ):
        assert marker in text


def test_generator_scenario_selection() -> None:
    lines = list(iter_lines(GeneratorSettings(lines=500, seed=1, scenarios=("dev_noise",))))
    assert not any("payment-provider" in line for line in lines)
    assert any("DEBUG" in line for line in lines)
    assert set(SCENARIOS) >= {"perf_degradation", "db_pool_exhaustion", "payment_cascade"}
