"""Log line parsers.

Three formats are supported out of the box (all three appear interleaved in the sample
data, so detection is per line, not per file):

* ``text`` - ``2024-01-10 10:15:23.456 ERROR [api-gateway] RequestID:abc123 message``
* ``json`` - one JSON object per line with timestamp/level/service/message keys
* ``app``  - Monolog/Laravel style ``[2024-01-10 10:15:26] production.ERROR: msg {json}``

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


class Parser(Protocol):
    """A log format. Implementations must be stateless and thread-safe."""

    name: str

    def parse(self, line: str, line_no: int) -> LogEvent | None:
        """Return an event, or ``None`` if ``line`` is not in this format."""


ParserFactory = Callable[[ParserConfig], Parser]
PARSERS: Registry[ParserFactory] = Registry("parser")


class TextParser:
    """``<timestamp> <LEVEL> [<service>] [RequestID:<id>] <message>``."""

    name = "text"
    _pattern = re.compile(
        rf"^(?P<ts>{_TS})\s+(?P<level>[A-Za-z]+)\s+\[(?P<service>[^\]]+)\]\s*"
        r"(?:(?:RequestID|request_id|req_id|rid)[:=](?P<rid>\S+)\s*)?(?P<msg>.*?)\s*$"
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
            message=match["msg"],
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
    _pattern = re.compile(
        rf"^\[(?P<ts>{_TS})\]\s+(?P<channel>[\w-]+(?:\.[\w-]+)*?)\.(?P<level>[A-Za-z]+):\s?(?P<msg>.*?)\s*$"
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
        message = self._trailing_extra.sub("", match["msg"])
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

    def __init__(self, config: ParserConfig) -> None:
        self._tz = ZoneInfo(config.default_timezone)
        self._ts_keys = config.json_timestamp_keys
        self._level_keys = config.json_level_keys
        self._service_keys = config.json_service_keys
        self._message_keys = config.json_message_keys
        self._rid_keys = config.json_request_id_keys
        self._consumed = frozenset(
            (*self._ts_keys, *self._level_keys, *self._service_keys, *self._message_keys,
             *self._rid_keys)
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
            service=str(service) if service not in (None, "") else "unknown",
            message=str(message) if message is not None else "",
            raw=line,
            fmt=self.name,
            request_id=str(rid) if rid not in (None, "") else None,
            fields=fields,
            line_no=line_no,
        )


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

    def parse(self, line: str, line_no: int = 0) -> LogEvent | None:
        for parser in self.parsers:
            event = parser.parse(line, line_no)
            if event is not None:
                return event
        return None


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
    for key in keys:
        if key in data:
            return data[key]
        if "." in key:  # nested lookup, e.g. "service.name"
            node: Any = data
            for part in key.split("."):
                node = node.get(part) if isinstance(node, dict) else None
            if node is not None:
                return node
    return None


def _first_str(data: Mapping[str, Any], keys: tuple[str, ...]) -> str | None:
    for key in keys:
        value = data.get(key)
        if isinstance(value, str) and value:
            return value
    return None
