"""HTTP API (spec: "API Input (optional)").

    POST /analyze   {"logs": ["line 1", "line 2"], "window": "5m"}  -> JSON report
    GET  /health    liveness/readiness probe

Each request is analyzed by a fresh, independent :class:`Analyzer` (the configuration is
immutable and shared), so the threaded server needs no locking. Request bodies and line
counts are capped by ``api.max_body_bytes`` / ``api.max_lines``.

The standard-library server keeps the image dependency-free; behind an ingress it is
adequate for this endpoint. A high-volume deployment would put the same ``Analyzer``
behind an ASGI server or, more likely, a message-queue consumer (see docs/DESIGN.md).
"""

from __future__ import annotations

import json
import logging
import signal
import threading
import time
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

from log_analyzer import __version__
from log_analyzer.config.schema import AnalyzerConfig
from log_analyzer.engine import Analyzer
from log_analyzer.output.report import report_dict
from log_analyzer.timeutil import parse_duration

log = logging.getLogger("log_analyzer.api")


class ApiError(Exception):
    def __init__(self, status: HTTPStatus, message: str) -> None:
        super().__init__(message)
        self.status = status
        self.message = message


def analyze_payload(config: AnalyzerConfig, payload: Any) -> dict[str, Any]:
    """Validate a request body and run the analysis (pure function, easy to test)."""
    if not isinstance(payload, dict):
        raise ApiError(HTTPStatus.BAD_REQUEST, "body must be a JSON object")
    unknown = sorted(set(payload) - {"logs", "window"})
    if unknown:
        raise ApiError(HTTPStatus.BAD_REQUEST, f"unknown field(s): {', '.join(unknown)}")
    logs = payload.get("logs")
    if not isinstance(logs, list) or not all(isinstance(line, str) for line in logs):
        raise ApiError(HTTPStatus.BAD_REQUEST, "'logs' must be a list of strings")
    if len(logs) > config.api.max_lines:
        raise ApiError(
            HTTPStatus.REQUEST_ENTITY_TOO_LARGE,
            f"too many lines ({len(logs)} > {config.api.max_lines})",
        )
    window: float | None = None
    if payload.get("window") is not None:
        try:
            window = parse_duration(payload["window"])
        except (TypeError, ValueError) as exc:
            raise ApiError(HTTPStatus.BAD_REQUEST, f"invalid 'window': {exc}") from exc
    analyzer = Analyzer(config)
    for line in logs:
        analyzer.process_line(line)
    return report_dict(analyzer.result(window))


def make_handler(config: AnalyzerConfig) -> type[BaseHTTPRequestHandler]:
    class Handler(BaseHTTPRequestHandler):
        server_version = f"log-analyzer/{__version__}"
        protocol_version = "HTTP/1.1"

        def do_GET(self) -> None:
            if self.path in ("/health", "/healthz"):
                self._send(HTTPStatus.OK, {"status": "ok", "version": __version__})
            elif self.path == "/analyze":
                self._error(HTTPStatus.METHOD_NOT_ALLOWED, "use POST /analyze")
            else:
                self._error(HTTPStatus.NOT_FOUND, f"no route for {self.path}")

        def do_POST(self) -> None:
            if self.path != "/analyze":
                self._error(HTTPStatus.NOT_FOUND, f"no route for {self.path}")
                return
            started = time.perf_counter()
            try:
                payload = self._read_json()
                body = analyze_payload(config, payload)
            except ApiError as exc:
                self._error(exc.status, exc.message)
                return
            except Exception:  # last-resort guard: never leak internals
                log.exception("unhandled error while analyzing request")
                self._error(HTTPStatus.INTERNAL_SERVER_ERROR, "internal error")
                return
            log.info(
                "analyzed %d lines in %.1fms -> %d alerts",
                body["statistics"]["total_logs"],
                (time.perf_counter() - started) * 1000,
                body["statistics"]["alerts_generated"],
            )
            self._send(HTTPStatus.OK, body)

        def _read_json(self) -> Any:
            length_header = self.headers.get("Content-Length")
            if length_header is None:
                raise ApiError(HTTPStatus.LENGTH_REQUIRED, "Content-Length header is required")
            try:
                length = int(length_header)
            except ValueError:
                raise ApiError(HTTPStatus.BAD_REQUEST, "invalid Content-Length") from None
            if length < 0 or length > config.api.max_body_bytes:
                raise ApiError(
                    HTTPStatus.REQUEST_ENTITY_TOO_LARGE,
                    f"body exceeds {config.api.max_body_bytes} bytes",
                )
            raw = self.rfile.read(length)
            try:
                return json.loads(raw.decode("utf-8"))
            except (UnicodeDecodeError, ValueError) as exc:
                raise ApiError(HTTPStatus.BAD_REQUEST, f"invalid JSON: {exc}") from exc

        def _error(self, status: HTTPStatus, message: str) -> None:
            self._send(status, {"error": message, "status": status.value})

        def _send(self, status: HTTPStatus, body: dict[str, Any]) -> None:
            data = json.dumps(body).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def log_message(self, format: str, *args: Any) -> None:
            log.info("%s %s", self.address_string(), format % args)

    return Handler


def create_server(
    config: AnalyzerConfig, host: str | None = None, port: int | None = None
) -> ThreadingHTTPServer:
    server = ThreadingHTTPServer(
        (host or config.api.host, config.api.port if port is None else port), make_handler(config)
    )
    server.daemon_threads = True
    return server


def serve(config: AnalyzerConfig, host: str | None = None, port: int | None = None) -> None:
    """Run until SIGINT/SIGTERM, then shut down gracefully."""
    server = create_server(config, host, port)
    bound_host, bound_port = server.server_address[:2]
    log.warning("log-analyzer API listening on http://%s:%s", bound_host, bound_port)

    def stop(signum: int, _frame: object) -> None:
        log.warning("received signal %d, shutting down", signum)
        threading.Thread(target=server.shutdown, daemon=True).start()

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    try:
        server.serve_forever()
    finally:
        server.server_close()
