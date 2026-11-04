"""Log line parsers.

Four formats are supported out of the box. The first three appear interleaved in the
sample data, so detection is per line, not per file:

* ``text`` - ``2024-01-10 10:15:23.456 ERROR [api-gateway] RequestID:abc123 message``
* ``json`` - one JSON object per line with timestamp/level/service/message keys
* ``app``  - Monolog/Laravel style ``[2024-01-10 10:15:26] production.ERROR: msg {json}``
* ``otel`` - OpenTelemetry log records in OTLP/JSON (single records or export batches)

A parser returns ``None`` when a line is not in its format, so the chain can try the next
one. Parsers are cheap to sniff (first character) and compile their regexes once.
"""

from __future__ import annotations

import json
import re
from collections.abc import Callable, Mapping
from typing import Any, Protocol
from zoneinfo import ZoneInfo

from log_analyzer.config.schema import ParserConfig
from log_analyzer.models import Level, LogEvent
from log_analyzer.plugins import PluginError, Registry, load_reference
from log_analyzer.timeutil import parse_timestamp

_TS = r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:[.,]\d+)?(?:Z|[+-]\d{2}:?\d{2})?"
_MAX_CONTEXT_ATTEMPTS = 4
_UNKNOWN_SERVICE = "unknown"  # structured records that name no service


class Parser(Protocol):
    """A log format. Implementations must be stateless and thread-safe.

    Parsers may define ``first_chars`` (a string of characters a line in this format
    can start with); the chain then only tries them on matching lines.
    """

    name: str

    def parse(self, line: str, line_no: int) -> LogEvent | None:
        """Return an event, or ``None`` if ``line`` is not in this format."""


ParserFactory = Callable[[ParserConfig], Parser]
# A parse function and whether it returns a list (batch formats) or a single event.
_Candidate = tuple[Callable[[str, int], Any], bool]
PARSERS: Registry[ParserFactory] = Registry("parser")


class TextParser:
    """``<timestamp> <LEVEL> [<service>] [RequestID:<id>] <message>``."""

    name = "text"
    first_chars = "0123456789"
    _pattern = re.compile(
        rf"^(?P<ts>{_TS})\s+(?P<level>[A-Za-z]+)\s+\[(?P<service>[^\]]+)\]\s*"
        r"(?:(?:RequestID|request_id|req_id|rid)[:=](?P<rid>\S+)\s*)?(?P<msg>.*)$"
    )

    def __init__(self, config: ParserConfig) -> None:
        self._tz = ZoneInfo(config.default_timezone)

    def parse(self, line: str, line_no: int) -> LogEvent | None:
        if not line[:1].isdigit():
            return None
        match = self._pattern.match(line)
        if match is None:
            return None
        try:
            level = Level.parse(match["level"])
            ts = parse_timestamp(match["ts"], self._tz)
        except ValueError:
            return None
        return LogEvent(
            ts=ts,
            level=level,
            service=match["service"].strip(),
            message=match["msg"].rstrip(),
            raw=line,
            fmt=self.name,
            request_id=match["rid"],
            line_no=line_no,
        )


class AppParser:
    """Monolog/Laravel: ``[<timestamp>] <channel>.<LEVEL>: <message> [<json context>]``.

    These lines carry no service name. The service is taken from the context's
    ``service`` key, else ``app_channel_services[channel]``, else ``app_default_service``.
    """

    name = "app"
    first_chars = "["
    _pattern = re.compile(
        rf"^\[(?P<ts>{_TS})\]\s+(?P<channel>[\w-]+(?:\.[\w-]+)*?)\.(?P<level>[A-Za-z]+):\s?(?P<msg>.*)$"
    )
    _trailing_extra = re.compile(r"\s+(?:\[\]|\{\})$")

    def __init__(self, config: ParserConfig) -> None:
        self._tz = ZoneInfo(config.default_timezone)
        self._channels: Mapping[str, str] = config.app_channel_services
        self._default_service = config.app_default_service

    def parse(self, line: str, line_no: int) -> LogEvent | None:
        if not line.startswith("["):
            return None
        match = self._pattern.match(line)
        if match is None:
            return None
        try:
            level = Level.parse(match["level"])
            ts = parse_timestamp(match["ts"], self._tz)
        except ValueError:
            return None
        message = self._trailing_extra.sub("", match["msg"].rstrip())
        context = _trailing_json_object(message)
        channel = match["channel"]
        fields: dict[str, Any] = {"channel": channel}
        if context:
            fields.update(_flatten(context))
        service = (
            _first_str(context, ("service", "service_name")) if context else None
        ) or self._channels.get(channel, self._default_service)
        request_id = _first_str(context, ("request_id", "requestId")) if context else None
        return LogEvent(
            ts=ts,
            level=level,
            service=service,
            message=message,
            raw=line,
            fmt=self.name,
            request_id=request_id,
            fields=fields,
            line_no=line_no,
        )


class JsonParser:
    """One JSON object per line. Key names are configurable (``parsers.json_*_keys``)."""

    name = "json"
    first_chars = "{"

    def __init__(self, config: ParserConfig) -> None:
        self._tz = ZoneInfo(config.default_timezone)
        self._ts_keys = config.json_timestamp_keys
        self._level_keys = config.json_level_keys
        self._service_keys = config.json_service_keys
        self._message_keys = config.json_message_keys
        self._rid_keys = config.json_request_id_keys
        self._consumed = frozenset(
            (
                *self._ts_keys,
                *self._level_keys,
                *self._service_keys,
                *self._message_keys,
                *self._rid_keys,
            )
        )

    def parse(self, line: str, line_no: int) -> LogEvent | None:
        if not line.startswith("{"):
            return None
        try:
            data = json.loads(line)
        except ValueError:
            return None
        if not isinstance(data, dict):
            return None
        ts_value = _lookup(data, self._ts_keys)
        if ts_value is None:
            return None
        try:
            ts = (
                float(ts_value)
                if isinstance(ts_value, int | float) and not isinstance(ts_value, bool)
                else parse_timestamp(str(ts_value), self._tz)
            )
            level_value = _lookup(data, self._level_keys)
            level = Level.parse(str(level_value)) if level_value is not None else Level.INFO
        except ValueError:
            return None
        service = _lookup(data, self._service_keys)
        message = _lookup(data, self._message_keys)
        rid = _lookup(data, self._rid_keys)
        fields = _flatten({k: v for k, v in data.items() if k not in self._consumed})
        return LogEvent(
            ts=ts,
            level=level,
            service=str(service) if service not in (None, "") else _UNKNOWN_SERVICE,
            message=str(message) if message is not None else "",
            raw=line,
            fmt=self.name,
            request_id=str(rid) if rid not in (None, "") else None,
            fields=fields,
            line_no=line_no,
        )


class OtelParser:
    """OpenTelemetry log records in OTLP/JSON form.

    Two shapes are accepted, one per line:

    * a single log record (OTel log data model): ``timeUnixNano``, ``severityText`` /
      ``severityNumber``, ``body``, ``attributes``, ``resource``, ``traceId``;
    * an OTLP export batch (what the OpenTelemetry Collector's file exporter writes):
      ``{"resourceLogs": [{"resource": ..., "scopeLogs": [{"logRecords": [...]}]}]}``.

    The service comes from the ``service.name`` resource attribute, and the trace id is
    used as the request id (it counts distinct failed requests).
    """

    name = "otel"
    first_chars = "{"
    _markers = ('"resourceLogs"', '"timeUnixNano"', '"observedTimeUnixNano"', '"severityNumber"')

    def __init__(self, config: ParserConfig) -> None:
        del config  # nothing configurable yet; the factory signature is shared

    def parse(self, line: str, line_no: int) -> LogEvent | None:
        events = self.parse_batch(line, line_no)
        return events[0] if events else None

    def parse_batch(self, line: str, line_no: int) -> list[LogEvent] | None:
        if not line.startswith("{") or not any(m in line for m in self._markers):
            return None
        try:
            data = json.loads(line)
        except ValueError:
            return None
        if not isinstance(data, dict):
            return None
        if isinstance(data.get("resourceLogs"), list):
            events = []
            for resource_logs in data["resourceLogs"]:
                if not isinstance(resource_logs, dict):
                    continue
                resource = _otel_attributes(resource_logs.get("resource"))
                for scope_logs in resource_logs.get("scopeLogs") or []:
                    records = scope_logs.get("logRecords") if isinstance(scope_logs, dict) else []
                    for record in records or []:
                        event = self._record(record, resource, line, line_no)
                        if event is not None:
                            events.append(event)
            return events or None
        event = self._record(data, _otel_attributes(data.get("resource")), line, line_no)
        return [event] if event is not None else None

    def _record(
        self, record: Any, resource: dict[str, Any], raw: str, line_no: int
    ) -> LogEvent | None:
        if not isinstance(record, dict):
            return None
        ts = _otel_time(record.get("timeUnixNano")) or _otel_time(
            record.get("observedTimeUnixNano")
        )
        if ts is None:
            return None
        level = _otel_level(record.get("severityText"), record.get("severityNumber"))
        attributes = _otel_attributes(record.get("attributes"))
        service = resource.get("service.name") or attributes.get("service.name")
        trace_id = record.get("traceId")
        fields = _flatten({**resource, **attributes})
        for key in ("traceId", "spanId"):
            if record.get(key):
                fields[key] = record[key]
        return LogEvent(
            ts=ts,
            level=level,
            service=str(service) if service else _UNKNOWN_SERVICE,
            message=_otel_value_text(record.get("body")),
            raw=raw,
            fmt=self.name,
            request_id=str(trace_id) if trace_id and set(str(trace_id)) != {"0"} else None,
            fields=fields,
            line_no=line_no,
        )


PARSERS.register("otel")(OtelParser)
PARSERS.register("text")(TextParser)
PARSERS.register("app")(AppParser)
PARSERS.register("json")(JsonParser)


class ParserChain:
    """Tries each enabled parser in turn. Plugins are tried before the built-ins."""

    def __init__(self, config: ParserConfig) -> None:
        parsers: list[Parser] = []
        for reference in config.plugins:
            factory = load_reference(reference)
            if not callable(factory):
                raise PluginError(f"parser plugin {reference!r} is not callable")
            parsers.append(factory(config))
        parsers.extend(PARSERS.get(name)(config) for name in config.enabled)
        self.parsers: tuple[Parser, ...] = tuple(parsers)
        self.max_line_length = config.max_line_length
        self._by_first_char: dict[str, tuple[_Candidate, ...]] = {}

    def parse(self, line: str, line_no: int = 0) -> LogEvent | None:
        """The first event in ``line``, or ``None``."""
        events = self.parse_all(line, line_no)
        return events[0] if events else None

    def parse_all(self, line: str, line_no: int = 0) -> list[LogEvent]:
        """Every event in ``line``: usually one, several for batch formats (OTLP), or none.

        A parser may define ``parse_batch(line, line_no) -> list[LogEvent] | None`` for
        formats that carry many records per line.
        """
        for parse, is_batch in self._candidates(line[:1]):
            result = parse(line, line_no)
            if result:
                return list(result) if is_batch else [result]
        return []

    def _candidates(self, first: str) -> tuple[_Candidate, ...]:
        """Parse functions worth trying for a line starting with ``first`` (cached)."""
        candidates = self._by_first_char.get(first)
        if candidates is None:
            candidates = tuple(
                (batch, True) if (batch := getattr(p, "parse_batch", None)) else (p.parse, False)
                for p in self.parsers
                if first in getattr(p, "first_chars", first or " ")
            )
            if len(self._by_first_char) < 256:
                self._by_first_char[first] = candidates
        return candidates


# ----------------------------------------------------------------------------- helpers
def _trailing_json_object(message: str) -> dict[str, Any] | None:
    """Extract a JSON object that ends the message (Monolog context), if any."""
    if not message.endswith("}"):
        return None
    start = message.find("{")
    attempts = 0
    while start != -1 and attempts < _MAX_CONTEXT_ATTEMPTS:
        try:
            value = json.loads(message[start:])
        except ValueError:
            start = message.find("{", start + 1)
            attempts += 1
            continue
        return value if isinstance(value, dict) else None
    return None


def _flatten(data: Mapping[str, Any], prefix: str = "") -> dict[str, Any]:
    """Flatten nested objects to dotted keys, also exposing un-prefixed leaf names.

    ``{"details": {"active_connections": 100}}`` yields both ``details.active_connections``
    and ``active_connections`` so metric extractors can use the short name.
    """
    flat: dict[str, Any] = {}
    for key, value in data.items():
        full = f"{prefix}{key}"
        if isinstance(value, dict):
            nested = _flatten(value, f"{full}.")
            flat.update(nested)
            for nested_key, nested_value in nested.items():
                flat.setdefault(nested_key.rsplit(".", 1)[-1], nested_value)
        else:
            flat[full] = value
    return flat


def _lookup(data: Mapping[str, Any], keys: tuple[str, ...]) -> Any:
    """First *scalar* value among ``keys``; dotted keys walk nested objects.

    Objects are skipped so that ECS-style ``{"service": {"name": "x"}}`` falls through
    from ``service`` to ``service.name``.
    """
    for key in keys:
        value = data.get(key)
        if value is None and "." in key:
            node: Any = data
            for part in key.split("."):
                node = node.get(part) if isinstance(node, dict) else None
            value = node
        if value is not None and not isinstance(value, dict | list):
            return value
    return None


# OTel severityNumber ranges (log data model): 1-4 TRACE, 5-8 DEBUG, 9-12 INFO,
# 13-16 WARN, 17-20 ERROR, 21-24 FATAL.
_OTEL_SEVERITY_FLOORS = (
    (21, Level.CRITICAL),
    (17, Level.ERROR),
    (13, Level.WARN),
    (9, Level.INFO),
    (1, Level.DEBUG),
)
_NANOS = 1_000_000_000
_OTEL_RESOURCE_KEYS = frozenset({"attributes", "droppedAttributesCount"})


def _otel_time(value: Any) -> float | None:
    """Epoch nanoseconds (JSON string or int) -> epoch seconds; 0 means "unset"."""
    if value is None or isinstance(value, bool):
        return None
    try:
        nanos = int(value)
    except (TypeError, ValueError):
        return None
    return nanos / _NANOS if nanos > 0 else None


def _otel_level(text: Any, number: Any) -> Level:
    if isinstance(text, str) and text:
        try:
            return Level.parse(text)
        except ValueError:
            pass
    if isinstance(number, int) and not isinstance(number, bool) and 1 <= number <= 24:
        return next(level for floor, level in _OTEL_SEVERITY_FLOORS if number >= floor)
    return Level.INFO  # severity is optional in OTel; unset means "no opinion"


def _otel_value(value: Any) -> Any:
    """Unwrap an OTLP AnyValue (``{"stringValue": "x"}``, ``{"intValue": "5"}``, ...)."""
    if not isinstance(value, dict):
        return value
    for key in ("stringValue", "boolValue", "doubleValue"):
        if key in value:
            return value[key]
    if "intValue" in value:
        try:
            return int(value["intValue"])
        except (TypeError, ValueError):
            return value["intValue"]
    if "arrayValue" in value:
        return [_otel_value(v) for v in value["arrayValue"].get("values") or []]
    if "kvlistValue" in value:
        return _otel_attributes(value["kvlistValue"].get("values"))
    return value


def _otel_value_text(body: Any) -> str:
    value = _otel_value(body)
    if value is None:
        return ""
    return value if isinstance(value, str) else json.dumps(value, sort_keys=True)


def _otel_attributes(data: Any) -> dict[str, Any]:
    """OTLP attributes (``[{"key": k, "value": AnyValue}]``) or a plain mapping -> dict.

    Accepts a ``resource`` object too (its ``attributes`` are used).
    """
    if (
        isinstance(data, dict)
        and isinstance(data.get("attributes"), list | dict)
        and set(data) <= _OTEL_RESOURCE_KEYS
    ):
        data = data["attributes"]
    if isinstance(data, list):
        return {
            str(item["key"]): _otel_value(item.get("value"))
            for item in data
            if isinstance(item, dict) and "key" in item
        }
    if isinstance(data, dict):
        return {str(k): _otel_value(v) for k, v in data.items()}
    return {}


def _first_str(data: Mapping[str, Any], keys: tuple[str, ...]) -> str | None:
    for key in keys:
        value = data.get(key)
        if isinstance(value, str) and value:
            return value
    return None
