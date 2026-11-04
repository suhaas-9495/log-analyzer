"""Command line interface.

    log-analyzer --file application.log --config config.yaml          # batch
    tail -f /var/log/app/*.log | log-analyzer --config config.yaml     # live stream
    log-analyzer serve --config config.yaml --port 8080                # HTTP API
    log-analyzer generate --lines 100000 --output logs.txt             # test data
    log-analyzer validate-config --config config.yaml

Exit codes: 0 ok, 1 runtime/config error, 2 usage error, 3 alerts at or above
``--fail-on`` severity (useful in CI or cron).
"""

from __future__ import annotations

import argparse
import logging
import os
import sys
import time
from collections import deque
from collections.abc import Iterable, Sequence
from pathlib import Path
from typing import TextIO

from log_analyzer import __version__
from log_analyzer.config import AnalyzerConfig, ConfigError, load_config
from log_analyzer.correlation.correlator import AlertEvent
from log_analyzer.engine import AnalysisResult, Analyzer
from log_analyzer.ingest.sources import LineReader, merged_events, open_text
from log_analyzer.models import LogEvent, Severity
from log_analyzer.output.console import ConsoleRenderer, use_color
from log_analyzer.output.report import event_json, report_json
from log_analyzer.plugins import PluginError
from log_analyzer.timeutil import parse_duration

log = logging.getLogger("log_analyzer")

EXIT_OK, EXIT_ERROR, EXIT_USAGE, EXIT_ALERTS = 0, 1, 2, 3
CONFIG_ENV = "LOG_ANALYZER_CONFIG"
_SUBCOMMANDS = ("serve", "generate", "validate-config")
_CLEAR_SCREEN = "\033[2J\033[H"
_RECENT_EVENTS = 8


def main(argv: Sequence[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    try:
        if args and args[0] in _SUBCOMMANDS:
            return _run_subcommand(args[0], args[1:])
        return _analyze(args)
    except (ConfigError, PluginError) as exc:
        print(f"configuration error: {exc}", file=sys.stderr)
        return EXIT_ERROR
    except OSError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_ERROR


# --------------------------------------------------------------------------- analyze
def _analyze_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="log-analyzer",
        description="Analyze logs, correlate failures and emit de-duplicated, root-caused "
        "alerts. Reads --file(s) or, if none are given, a live stream on stdin.",
        epilog=f"Other commands: {', '.join(_SUBCOMMANDS)} (use '<command> --help').",
    )
    parser.add_argument(
        "-f",
        "--file",
        action="append",
        default=[],
        metavar="PATH",
        help="log file to analyze (.gz supported); repeat to merge several files by "
        "timestamp; '-' reads stdin",
    )
    _add_config_argument(parser)
    parser.add_argument(
        "--format",
        choices=("console", "json", "jsonl"),
        default="console",
        help="console dashboard, a JSON report, or JSON-lines alert events (default: console)",
    )
    parser.add_argument("-o", "--output", metavar="PATH", help="write the final report here")
    parser.add_argument(
        "--window",
        metavar="DURATION",
        help="report on the trailing window only, e.g. 5m (default: everything read)",
    )
    parser.add_argument(
        "--events",
        action="store_true",
        help="also print alert lifecycle events (NEW/UPDATED/RESOLVED) as they occur",
    )
    parser.add_argument("--color", choices=("auto", "always", "never"), help="colorize output")
    parser.add_argument(
        "--fail-on",
        choices=[s.name for s in Severity],
        metavar="SEVERITY",
        help="exit with code 3 if any alert is at or above this severity",
    )
    _add_log_level_argument(parser)
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return parser


def _analyze(argv: list[str]) -> int:
    args = _analyze_parser().parse_args(argv)
    _setup_logging(args.log_level)
    config = _load(args.config)
    window = _duration_arg(args.window)
    files = [f for f in args.file if f != "-"]
    use_stdin = not args.file or "-" in args.file
    if use_stdin and files:
        print("error: cannot combine '-' (stdin) with --file paths", file=sys.stderr)
        return EXIT_USAGE
    if use_stdin and sys.stdin.isatty():
        print("error: no input. Pass --file PATH or pipe logs on stdin.", file=sys.stderr)
        return EXIT_USAGE
    analyzer = Analyzer(config)
    color = use_color(args.color or config.output.color, sys.stdout)
    renderer = ConsoleRenderer(color=color, max_trend_rows=config.output.max_trend_rows)
    printer = _EventPrinter(args.format, renderer, analyzer, enabled=args.events or use_stdin)
    interrupted = False
    try:
        if use_stdin:
            _stream_stdin(
                analyzer, printer, renderer, config, window, live=args.format == "console"
            )
        else:
            _process_files(analyzer, files, printer)
    except KeyboardInterrupt:
        interrupted = True
        log.info("interrupted; writing report for the input read so far")
    result = analyzer.result(window)
    _emit_final(result, args.format, renderer, args.output, color_file=False)
    log.info(
        "processed %d lines in %.2fs (%d alerts)",
        result.stats.lines_read,
        result.processing_seconds,
        len(result.alerts),
    )
    if args.fail_on and any(a.severity >= Severity[args.fail_on] for a in result.alerts):
        return EXIT_ALERTS
    return 130 if interrupted and not use_stdin else EXIT_OK


def _process_files(analyzer: Analyzer, files: list[str], printer: _EventPrinter) -> None:
    if len(files) == 1:
        with open_text(files[0]) as handle:
            for line in handle:
                printer.emit(analyzer.process_line(line))
        return
    events: Iterable[LogEvent] = merged_events(files, analyzer.parse_line)
    for event in events:
        printer.emit(analyzer.process_event(event))


def _stream_stdin(
    analyzer: Analyzer,
    printer: _EventPrinter,
    renderer: ConsoleRenderer,
    config: AnalyzerConfig,
    window: float | None,
    *,
    live: bool,
) -> None:
    """Analyze stdin as it arrives; redraw a live dashboard on a terminal."""
    refresh = config.output.refresh_seconds
    dashboard = live and sys.stdout.isatty()
    printer.quiet = dashboard  # events are shown inside the redrawn dashboard instead
    last_line_wall = time.monotonic()
    next_draw = time.monotonic() + refresh
    for line in LineReader(sys.stdin).lines(timeout=refresh):
        now_wall = time.monotonic()
        if line is None:
            # Idle: live logs mean event time keeps moving, so let quiet incidents close.
            watermark = analyzer.watermark
            if watermark is not None:
                printer.emit(analyzer.advance_clock(watermark + (now_wall - last_line_wall)))
                last_line_wall = now_wall
        else:
            printer.emit(analyzer.process_line(line))
            last_line_wall = now_wall
        if dashboard and now_wall >= next_draw:
            frame = renderer.dashboard(
                analyzer.result(window or config.windows.dashboard), live=True
            )
            recent = "\n".join(printer.recent) or "  (none yet)"
            sys.stdout.write(f"{_CLEAR_SCREEN}{frame}\n\nRECENT ALERT EVENTS:\n{recent}\n")
            sys.stdout.flush()
            next_draw = now_wall + refresh


class _EventPrinter:
    """Prints alert lifecycle events in the selected format as they happen."""

    def __init__(
        self, fmt: str, renderer: ConsoleRenderer, analyzer: Analyzer, *, enabled: bool
    ) -> None:
        self._fmt = fmt
        self._renderer = renderer
        self._analyzer = analyzer
        self._enabled = enabled or fmt == "jsonl"
        self.quiet = False
        self.recent: deque[str] = deque(maxlen=_RECENT_EVENTS)

    def emit(self, events: list[AlertEvent]) -> None:
        if not self._enabled:
            return
        for event in events:
            if self._fmt == "jsonl":
                view = self._analyzer.correlator.builder.build(event.incident, event.assessment)
                print(event_json(event, view.to_dict()), flush=True)
            elif self._fmt == "console":
                text = self._renderer.event(event)
                self.recent.append(text)
                if not self.quiet:
                    print(text, flush=True)


def _emit_final(
    result: AnalysisResult,
    fmt: str,
    renderer: ConsoleRenderer,
    output: str | None,
    *,
    color_file: bool,
) -> None:
    if fmt == "console":
        text = renderer.dashboard(result)
        if output:
            plain = ConsoleRenderer(color=color_file).dashboard(result)
            Path(output).write_text(plain + "\n", encoding="utf-8")
        else:
            print(text)
        return
    payload = report_json(result)
    if fmt == "jsonl":
        payload = '{"event": "SUMMARY", "report": ' + report_json(result, indent=None) + "}"
    if output:
        Path(output).write_text(payload + "\n", encoding="utf-8")
    else:
        print(payload)


# ------------------------------------------------------------------------ subcommands
def _run_subcommand(name: str, argv: list[str]) -> int:
    if name == "serve":
        return _serve(argv)
    if name == "generate":
        return _generate(argv)
    return _validate(argv)


def _serve(argv: list[str]) -> int:
    from log_analyzer.api.server import serve  # noqa: PLC0415 - only needed in API mode

    parser = argparse.ArgumentParser(prog="log-analyzer serve", description="Run the HTTP API.")
    _add_config_argument(parser)
    parser.add_argument("--host", help="bind address (default: api.host from config)")
    parser.add_argument("--port", type=int, help="port (default: api.port from config)")
    _add_log_level_argument(parser)
    args = parser.parse_args(argv)
    _setup_logging(args.log_level)
    config = _load(args.config)
    serve(config, host=args.host, port=args.port)
    return EXIT_OK


def _generate(argv: list[str]) -> int:
    from log_analyzer.testdata.generator import SCENARIOS, GeneratorSettings, generate  # noqa: PLC0415

    parser = argparse.ArgumentParser(
        prog="log-analyzer generate",
        description="Generate realistic multi-format test logs with injected incidents.",
    )
    parser.add_argument("--lines", type=int, default=10_000, help="approximate line count")
    parser.add_argument("--seed", type=int, default=42, help="random seed (deterministic)")
    parser.add_argument("--start", default="2025-10-07T14:00:00", help="first timestamp (UTC)")
    parser.add_argument(
        "--scenarios",
        default=",".join(SCENARIOS),
        help=f"comma-separated incidents to inject (available: {', '.join(SCENARIOS)})",
    )
    parser.add_argument("-o", "--output", help="output file (default: stdout)")
    args = parser.parse_args(argv)
    scenarios = tuple(s.strip() for s in args.scenarios.split(",") if s.strip())
    unknown = sorted(set(scenarios) - set(SCENARIOS))
    if unknown:
        parser.error(f"unknown scenario(s): {', '.join(unknown)}")
    settings = GeneratorSettings(
        lines=args.lines, seed=args.seed, start=args.start, scenarios=scenarios
    )
    out: TextIO
    if args.output:
        Path(args.output).parent.mkdir(parents=True, exist_ok=True)
        with open(args.output, "w", encoding="utf-8") as out:
            count = generate(settings, out)
        print(f"wrote {count:,} lines to {args.output}", file=sys.stderr)
    else:
        generate(settings, sys.stdout)
    return EXIT_OK


def _validate(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(
        prog="log-analyzer validate-config", description="Validate a configuration file."
    )
    _add_config_argument(parser, required=True)
    args = parser.parse_args(argv)
    config = _load(args.config)
    print(f"OK: {args.config}")
    print(f"  services:      {len(config.services)}")
    print(f"  patterns:      {len(config.patterns)}")
    print(f"  metrics:       {len(config.metrics)}")
    print(f"  alert rules:   {', '.join(r.name for r in config.alert_rules) or '-'}")
    print(
        f"  ignore rules:  {len(config.filters.ignore_patterns)} patterns, "
        f"{len(config.filters.ignore_services)} services, min level {config.filters.min_level.name}"
    )
    return EXIT_OK


# ---------------------------------------------------------------------------- helpers
def _add_config_argument(parser: argparse.ArgumentParser, *, required: bool = False) -> None:
    parser.add_argument(
        "-c",
        "--config",
        required=required,
        default=None if required else os.environ.get(CONFIG_ENV),
        metavar="PATH",
        help=f"YAML config (default: ${CONFIG_ENV}, else built-in defaults)",
    )


def _add_log_level_argument(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--log-level",
        default=os.environ.get("LOG_ANALYZER_LOG_LEVEL", "WARNING"),
        choices=("DEBUG", "INFO", "WARNING", "ERROR"),
        help="diagnostic logging on stderr",
    )


def _setup_logging(level: str) -> None:
    logging.basicConfig(
        level=getattr(logging, level),
        stream=sys.stderr,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )


def _load(path: str | None) -> AnalyzerConfig:
    config = load_config(path)
    log.info("configuration loaded from %s", path or "built-in defaults")
    return config


def _duration_arg(value: str | None) -> float | None:
    if value is None:
        return None
    try:
        return parse_duration(value)
    except ValueError as exc:
        raise ConfigError("--window", str(exc)) from exc


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
