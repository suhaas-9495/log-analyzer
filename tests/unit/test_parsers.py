from __future__ import annotations

import json

import pytest

from log_analyzer.config import build_config
from log_analyzer.config.schema import ParserConfig
from log_analyzer.ingest.parsers import (
    PARSERS,
    AppParser,
    JsonParser,
    OtelParser,
    ParserChain,
    TextParser,
)
from log_analyzer.models import Level
from log_analyzer.plugins import PluginError
from log_analyzer.timeutil import parse_timestamp

CFG = ParserConfig()


class TestTextParser:
    parser = TextParser(CFG)

    def test_spec_example_with_request_id(self) -> None:
        event = self.parser.parse(
            "2024-01-10 10:15:23.456 ERROR [api-gateway] RequestID:abc123 "
            "Connection timeout to payment-service after 30000ms",
            7,
        )
        assert event is not None
        assert event.level is Level.ERROR
        assert event.service == "api-gateway"
        assert event.request_id == "abc123"
        assert event.message == "Connection timeout to payment-service after 30000ms"
        assert event.ts == parse_timestamp("2024-01-10T10:15:23.456")
        assert event.line_no == 7
        assert event.fmt == "text"

    def test_without_milliseconds_or_request_id_and_padded_level(self) -> None:
        event = self.parser.parse("2024-01-10 10:00:00 WARN  [database] Connection pool: 95/100", 1)
        assert event is not None
        assert event.level is Level.WARN
        assert event.request_id is None
        assert event.message == "Connection pool: 95/100"

    @pytest.mark.parametrize(
        "line",
        [
            "not a log line",
            "2024-01-10 10:00:00 BOGUS [svc] message",  # unknown level
            "2024-13-45 99:99:99 ERROR [svc] message",  # impossible timestamp
            "[2024-01-10 10:00:00] production.ERROR: other format",
        ],
    )
    def test_rejects_other_lines(self, line: str) -> None:
        assert self.parser.parse(line, 1) is None


class TestJsonParser:
    parser = JsonParser(CFG)

    def test_spec_example_flattens_nested_details(self) -> None:
        event = self.parser.parse(
            '{"timestamp":"2024-01-10T10:15:25.123Z","level":"ERROR","service":"payment-service",'
            '"request_id":"ghi789","message":"Database connection pool exhausted",'
            '"details":{"active_connections":100,"max_connections":100,"waiting_requests":15}}',
            1,
        )
        assert event is not None
        assert event.service == "payment-service"
        assert event.request_id == "ghi789"
        assert event.fields["details.active_connections"] == 100
        assert event.fields["max_connections"] == 100  # short alias for metric extractors
        assert "message" not in event.fields

    def test_defaults_for_missing_level_and_service_and_epoch_timestamp(self) -> None:
        event = self.parser.parse('{"ts": 1704881725.5, "msg": "hello"}', 1)
        assert event is not None
        assert event.level is Level.INFO
        assert event.service == "unknown"
        assert event.message == "hello"
        assert event.ts == 1704881725.5

    def test_nested_service_name_key(self) -> None:
        event = self.parser.parse(
            '{"@timestamp":"2024-01-10T10:00:00Z","level":"warning","service":{"name":"x"},'
            '"message":"m"}',
            1,
        )
        assert event is not None
        assert event.service == "x"
        assert event.level is Level.WARN

    @pytest.mark.parametrize(
        "line",
        [
            '{"broken json',
            "[1, 2, 3]",
            '{"level": "ERROR", "message": "no timestamp"}',
            '{"timestamp": "yesterday", "message": "bad ts"}',
            '{"timestamp": "2024-01-10T10:00:00Z", "level": "LOUD", "message": "bad level"}',
            "plain text",
        ],
    )
    def test_rejects_invalid(self, line: str) -> None:
        assert self.parser.parse(line, 1) is None


class TestAppParser:
    parser = AppParser(CFG)

    def test_spec_example_extracts_trailing_context(self) -> None:
        event = self.parser.parse(
            "[2024-01-10 10:15:26] production.ERROR: Unhandled exception in OrderController "
            '{"exception":"PaymentGatewayException","message":"Payment provider unavailable",'
            '"user_id":12345,"order_id":67890}',
            1,
        )
        assert event is not None
        assert event.level is Level.ERROR
        assert event.service == "app"  # app_default_service
        assert event.fields["channel"] == "production"
        assert event.fields["exception"] == "PaymentGatewayException"
        assert "Payment provider unavailable" in event.message  # context stays searchable

    def test_channel_mapping_service_from_context_and_monolog_extra(self) -> None:
        mapped = AppParser(ParserConfig(app_channel_services={"production": "web-app"}))
        event = mapped.parse("[2024-01-10 10:15:26] production.INFO: Configuration reloaded ", 1)
        assert event is not None
        assert event.service == "web-app"
        assert event.message == "Configuration reloaded"
        ctx = mapped.parse(
            '[2024-01-10 10:15:26] production.WARNING: slow {"service":"billing"} []', 1
        )
        assert ctx is not None
        assert ctx.service == "billing"
        assert ctx.level is Level.WARN

    def test_message_ending_in_brace_that_is_not_json(self) -> None:
        event = self.parser.parse("[2024-01-10 10:15:26] production.ERROR: weird {not json}", 1)
        assert event is not None
        assert event.fields == {"channel": "production"}

    def test_rejects_other_formats(self) -> None:
        assert self.parser.parse("2024-01-10 10:00:00 INFO [svc] text", 1) is None
        assert self.parser.parse("[not a timestamp] production.ERROR: x", 1) is None
        assert self.parser.parse("[2024-01-10 10:15:26] production.NOPE: x", 1) is None


def _attr(key: str, value: object) -> dict[str, object]:
    if isinstance(value, bool):
        wrapped: dict[str, object] = {"boolValue": value}
    elif isinstance(value, int):
        wrapped = {"intValue": str(value)}  # OTLP/JSON encodes 64-bit ints as strings
    else:
        wrapped = {"stringValue": value}
    return {"key": key, "value": wrapped}


T_NANOS = "1704881725123000000"  # 2024-01-10T10:15:25.123Z


class TestOtelParser:
    parser = OtelParser(CFG)

    def test_single_record_in_otlp_json(self) -> None:
        record = {
            "timeUnixNano": T_NANOS,
            "severityText": "ERROR",
            "severityNumber": 17,
            "body": {"stringValue": "Database connection pool exhausted"},
            "traceId": "5b8efff798038103d269b633813fc60c",
            "spanId": "eee19b7ec3c1b174",
            "attributes": [_attr("active_connections", 100), _attr("retry", True)],
            "resource": {"attributes": [_attr("service.name", "payment-service")]},
        }
        event = self.parser.parse(json.dumps(record), 7)
        assert event is not None
        assert event.fmt == "otel"
        assert event.ts == pytest.approx(1704881725.123)
        assert event.level is Level.ERROR
        assert event.service == "payment-service"
        assert event.message == "Database connection pool exhausted"
        assert event.request_id == "5b8efff798038103d269b633813fc60c"
        assert event.fields["active_connections"] == 100
        assert event.fields["retry"] is True
        assert event.fields["spanId"] == "eee19b7ec3c1b174"
        assert event.line_no == 7

    def test_export_batch_yields_every_record(self) -> None:
        batch = {
            "resourceLogs": [
                {
                    "resource": {"attributes": [_attr("service.name", "api-gateway")]},
                    "scopeLogs": [
                        {
                            "logRecords": [
                                {
                                    "timeUnixNano": T_NANOS,
                                    "severityNumber": 9,
                                    "body": {"stringValue": "ok"},
                                },
                                {
                                    "timeUnixNano": T_NANOS,
                                    "severityNumber": 17,
                                    "body": {"stringValue": "boom"},
                                },
                                "not a record",
                            ]
                        }
                    ],
                },
                {
                    "resource": {"attributes": [_attr("service.name", "database")]},
                    "scopeLogs": [
                        {"logRecords": [{"observedTimeUnixNano": T_NANOS, "body": "plain"}]}
                    ],
                },
                "not a resource",
            ]
        }
        events = ParserChain(CFG).parse_all(json.dumps(batch), 3)
        assert [(e.service, e.level, e.message) for e in events] == [
            ("api-gateway", Level.INFO, "ok"),
            ("api-gateway", Level.ERROR, "boom"),
            ("database", Level.INFO, "plain"),
        ]

    @pytest.mark.parametrize(
        ("text", "number", "level"),
        [
            ("WARN", None, Level.WARN),
            ("Information", 9, Level.INFO),
            (None, 2, Level.DEBUG),
            (None, 13, Level.WARN),
            (None, 21, Level.CRITICAL),
            ("Weird", 18, Level.ERROR),
            ("Weird", None, Level.INFO),
            (None, None, Level.INFO),
        ],
    )
    def test_severity_text_then_number(
        self, text: str | None, number: int | None, level: Level
    ) -> None:
        record: dict[str, object] = {"timeUnixNano": T_NANOS, "body": "x"}
        if text is not None:
            record["severityText"] = text
        if number is not None:
            record["severityNumber"] = number
        event = self.parser.parse(json.dumps(record), 1)
        assert event is not None
        assert event.level is level

    def test_structured_body_flat_resource_and_attribute_service(self) -> None:
        record = {
            "timeUnixNano": int(T_NANOS),
            "body": {"kvlistValue": {"values": [_attr("order_id", 42)]}},
            "resource": {"host.name": "node-1"},
            "attributes": {"service.name": "order-service"},
            "traceId": "00000000000000000000000000000000",
        }
        event = self.parser.parse(json.dumps(record), 1)
        assert event is not None
        assert event.message == '{"order_id": 42}'
        assert event.service == "order-service"
        assert event.fields["host.name"] == "node-1"
        assert event.request_id is None  # an all-zero trace id means "no trace"

    def test_any_value_variants(self) -> None:
        record = {
            "timeUnixNano": T_NANOS,
            "body": {"arrayValue": {"values": [{"stringValue": "a"}, {"doubleValue": 1.5}]}},
            "attributes": [{"key": "n", "value": {"intValue": "not-a-number"}}, {"value": {}}],
        }
        event = self.parser.parse(json.dumps(record), 1)
        assert event is not None
        assert event.message == '["a", 1.5]'
        assert event.service == "unknown"
        assert event.fields == {"n": "not-a-number"}

    @pytest.mark.parametrize(
        "line",
        [
            '{"timestamp":"2024-01-10T10:00:00Z","message":"plain json"}',  # no OTel markers
            '{"timeUnixNano": "1", broken',
            '["timeUnixNano"]',
            '{"timeUnixNano": "0", "body": "unset time and no observed time"}',
            '{"timeUnixNano": true, "body": "x"}',
            '{"timeUnixNano": "soon", "body": "x"}',
            '{"resourceLogs": []}',
            "2024-01-10 10:00:00 INFO [a] timeUnixNano",
        ],
    )
    def test_rejects_non_otel_lines(self, line: str) -> None:
        assert self.parser.parse(line, 1) is None

    def test_plain_json_still_goes_to_the_json_parser(self) -> None:
        event = ParserChain(CFG).parse('{"timestamp":"2024-01-10T10:00:00Z","message":"x"}')
        assert event is not None
        assert event.fmt == "json"


class TestParserChain:
    def test_dispatches_mixed_formats(self) -> None:
        chain = ParserChain(CFG)
        assert chain.parse("2024-01-10 10:00:00 INFO [a] x").fmt == "text"  # type: ignore[union-attr]
        assert chain.parse('{"timestamp":"2024-01-10T10:00:00Z","message":"x"}').fmt == "json"  # type: ignore[union-attr]
        assert chain.parse("[2024-01-10 10:00:00] production.INFO: x").fmt == "app"  # type: ignore[union-attr]
        assert chain.parse("garbage") is None
        assert chain.parse("") is None

    def test_only_enabled_parsers_are_used(self) -> None:
        chain = ParserChain(ParserConfig(enabled=("json",)))
        assert chain.parse("2024-01-10 10:00:00 INFO [a] x") is None

    def test_plugin_parser_is_tried_first(self) -> None:
        config = build_config({"parsers": {"plugins": ["tests.unit.plugin_examples:PipeParser"]}})
        chain = ParserChain(config.parsers)
        event = chain.parse("1704880800|ERROR|billing|card declined")
        assert event is not None
        assert event.fmt == "pipe"
        assert event.service == "billing"

    def test_bad_plugin_references(self) -> None:
        for ref in (
            "nope",
            "missing.module:X",
            "tests.unit.plugin_examples:Missing",
            "tests.unit.plugin_examples:NOT_CALLABLE",
        ):
            with pytest.raises(PluginError):
                ParserChain(ParserConfig(plugins=(ref,)))

    def test_unknown_parser_name(self) -> None:
        with pytest.raises(PluginError, match="unknown parser"):
            ParserChain(ParserConfig(enabled=("xml",)))

    def test_registry_lists_builtins_and_rejects_duplicates(self) -> None:
        assert {"text", "json", "app", "otel"} <= set(PARSERS.names())
        with pytest.raises(PluginError, match="already registered"):
            PARSERS.register("text")(TextParser)
