from __future__ import annotations

import pytest

from log_analyzer.config import AnalyzerConfig, build_config
from log_analyzer.correlation.topology import ServiceDirectory
from log_analyzer.models import Category, Level, Severity, SignalSource
from log_analyzer.processing.classifier import PatternClassifier
from log_analyzer.processing.filters import EventFilter, FilterReason
from log_analyzer.processing.metrics import MetricExtractor
from log_analyzer.processing.templates import template_of
from tests.conftest import EventFactory


# ----------------------------------------------------------------------------- filters
class TestEventFilter:
    def test_level_service_glob_and_pattern(self, make_event: EventFactory) -> None:
        config = build_config({
            "filters": {"min_level": "INFO", "ignore_services": ["dev-*", "localhost"]},
            "ignore_patterns": ["Health check endpoint", "(?i)hot reload"],
        })
        f = EventFilter(config.filters)
        assert f.reason(make_event(level=Level.DEBUG)) is FilterReason.LEVEL
        assert f.reason(make_event(service="dev-server")) is FilterReason.SERVICE
        assert f.reason(make_event(service="LOCALHOST")) is FilterReason.SERVICE
        assert f.reason(make_event("GET Health check endpoint")) is FilterReason.PATTERN
        assert f.reason(make_event("Starting HOT RELOAD")) is FilterReason.PATTERN
        assert f.reason(make_event("real problem", service="api")) is None

    def test_spec_debug_development_pattern_matches_raw_line(self) -> None:
        config = build_config({"filters": {"min_level": "DEBUG"}})
        f = EventFilter(config.filters)
        from tests.conftest import event

        dev = event("development build started", level=Level.DEBUG)
        assert f.reason(dev) is FilterReason.PATTERN  # raw line is "DEBUG [svc] development..."


# ---------------------------------------------------------------------------- templates
@pytest.mark.parametrize(
    ("message", "expected"),
    [
        ("Connection timeout to payment-service after 30000ms",
         "Connection timeout to payment-service after <*>"),
        ("Request processed in ord_78642ms", "Request processed in <*>"),
        ('Customer order failed {"order_id": "ord_1"}', 'Customer order failed {"order_id": "<*>"}'),
        ("Payment processed for amount $808.15", "Payment processed for amount <*>"),
        ("Deadlock detected", "Deadlock detected"),
    ],
)
def test_template_of(message: str, expected: str) -> None:
    assert template_of(message) == expected


# ------------------------------------------------------------------------------ metrics
class TestMetricExtractor:
    extractor = MetricExtractor(build_config().metrics)

    def test_latency_from_text_and_fields(self, make_event: EventFactory) -> None:
        text = self.extractor.extract(make_event("Request processed in 145ms", level=Level.INFO))
        assert [(s.metric, s.value) for s in text] == [("request_latency", 145.0)]
        query = self.extractor.extract(make_event("Slow query detected: 4564ms"))
        assert [(s.metric, s.value) for s in query] == [("db_query_time", 4564.0)]
        field = self.extractor.extract(
            make_event("Slow query detected", fields={"execution_time_ms": 177})
        )
        assert [(s.metric, s.value) for s in field] == [("db_query_time", 177.0)]

    @pytest.mark.parametrize(
        "message",
        ["Request processed in ord_78642ms", "Request took file_e54c7845.txtms to complete",
         "Response time degraded to usr_3521ms", "Background job completed in 4521ms"],
    )
    def test_garbled_or_irrelevant_values_are_ignored(
        self, make_event: EventFactory, message: str
    ) -> None:
        assert self.extractor.extract(make_event(message)) == []

    def test_utilization_from_text_and_fields(self, make_event: EventFactory) -> None:
        (text,) = self.extractor.extract(make_event("Connection pool: 95/100 active"))
        assert text.kind == "utilization"
        assert text.value == pytest.approx(0.95)
        assert (text.used, text.capacity) == (95, 100)
        (field,) = self.extractor.extract(
            make_event("Connection pool status",
                       fields={"active_connections": 50, "max_connections": 100})
        )
        assert field.value == pytest.approx(0.5)

    @pytest.mark.parametrize(
        "fields",
        [{"active_connections": 5, "max_connections": 0},
         {"active_connections": 500, "max_connections": 100},
         {"active_connections": "many", "max_connections": 100},
         {"active_connections": -1, "max_connections": 100}],
    )
    def test_invalid_utilization_is_ignored(self, make_event: EventFactory, fields: dict[str, object]) -> None:
        assert self.extractor.extract(make_event("Connection pool status", fields=fields)) == []

    def test_min_level_is_respected(self, make_event: EventFactory) -> None:
        config = build_config({"metrics": [{"name": "request_latency", "kind": "latency",
                                            "regex": "in (?P<value>\\d+)ms", "min_level": "WARN"}]})
        extractor = MetricExtractor(config.metrics)
        assert extractor.extract(make_event("done in 5ms", level=Level.INFO)) == []
        assert len(extractor.extract(make_event("done in 5ms", level=Level.WARN))) == 1


# ---------------------------------------------------------------------------- topology
class TestServiceDirectory:
    def test_resolve_mentions_and_plausibility(self, topology_config: AnalyzerConfig) -> None:
        d = ServiceDirectory(topology_config)
        assert d.resolve("Payment-Service") == "payment-service"
        assert d.resolve("payment") == "payment-service"
        assert d.resolve("file_007f1c1f") is None
        assert d.resolve(None) is None
        # longest alias wins: "payment provider" is not "payment" + "provider"
        assert d.mentions("Payment provider unavailable") == {"payment-provider"}
        assert d.mentions("Cannot process order: payment unavailable") == {
            "order-service", "payment-service"
        }
        assert d.mentions("user-servicems") == set()
        assert d.plausible("order-service", "database")
        assert not d.plausible("order-service", "api-gateway")  # wrong direction
        assert d.plausible("unknown-service", "anything")  # no topology -> trust the log
        assert d.static_edges({"order-service", "database", "web-app"}) == {
            ("order-service", "database")
        }
        assert d.linked("database", "order-service")
        assert d.dependencies("web-app") == {"api-gateway", "payment-service"}

    def test_observed_services_become_resolvable(self) -> None:
        d = ServiceDirectory(build_config(), max_observed=2)
        assert d.mentions("billing timed out") == {"database"} - {"database"}
        d.observe("billing")
        d.observe("billing")
        assert d.mentions("billing timed out") == {"billing"}
        d.observe("a")
        d.observe("b")  # evicts the oldest observed service
        assert d.resolve("billing") == "billing"  # names already learned stay resolvable


# --------------------------------------------------------------------------- classifier
class TestPatternClassifier:
    @pytest.fixture
    def classifier(self, topology_config: AnalyzerConfig) -> PatternClassifier:
        return PatternClassifier(topology_config, ServiceDirectory(topology_config))

    def test_connection_timeout_captures_target_and_backdates_failure(
        self, classifier: PatternClassifier, make_event: EventFactory
    ) -> None:
        signal = classifier.classify(make_event(
            "Connection timeout to payment-service after 30000ms", service="api-gateway"))
        assert signal is not None
        assert signal.kind == "connection_timeout"
        assert signal.targets == {"payment-service"}
        assert signal.fingerprint == ("connection_timeout", "api-gateway", "payment-service")
        assert signal.effective_ts == pytest.approx(signal.ts - 30.0)
        assert signal.start_ts == signal.effective_ts
        assert signal.is_failure

    def test_unknown_and_implausible_targets_are_dropped(
        self, classifier: PatternClassifier, make_event: EventFactory
    ) -> None:
        garbage = classifier.classify(make_event(
            "Connection timeout to file_007f1c1f.txt after user-servicems", service="api-gateway"))
        assert garbage is not None
        assert garbage.targets == frozenset()
        assert garbage.effective_ts is None
        wrong_way = classifier.classify(make_event(
            "Failed to connect to api-gateway: timeout", service="order-service"))
        assert wrong_way is not None
        assert wrong_way.targets == frozenset()  # order-service does not call the gateway

    def test_static_rule_target_and_alias_mentions(
        self, classifier: PatternClassifier, make_event: EventFactory
    ) -> None:
        pool = classifier.classify(make_event(
            "Failed to acquire database connection: pool exhausted", service="order-service"))
        assert pool is not None
        assert pool.kind == "db_pool_exhausted"
        assert pool.targets == {"database"}
        refused = classifier.classify(make_event(
            "Payment provider unavailable: connection refused", service="payment-service"))
        assert refused is not None
        assert refused.targets == {"payment-provider"}
        own = classifier.classify(make_event("Connection pool exhausted", service="database"))
        assert own is not None
        assert own.targets == frozenset()  # a service never targets itself

    def test_thresholds_value_ranges_and_garbled_numbers(
        self, classifier: PatternClassifier, make_event: EventFactory
    ) -> None:
        slow = classifier.classify(make_event("Query took 1500ms", level=Level.INFO))
        assert slow is not None
        assert slow.kind == "database_slow_query"
        assert slow.attributes["value"] == 1500
        assert classifier.classify(make_event("Query took 900ms", level=Level.INFO)) is None
        assert classifier.classify(make_event("Query took ord_1500ms", level=Level.INFO)) is None
        structured = classifier.classify(make_event(
            "Slow query detected", level=Level.WARN, fields={"execution_time_ms": 2500}))
        assert structured is not None
        assert structured.kind == "database_slow_query"
        cpu = classifier.classify(make_event("CPU usage at 95%", level=Level.WARN))
        assert cpu is not None
        assert cpu.kind == "high_cpu_usage"
        # "CPU usage at 3748%" is not a real reading: outside value_range
        impossible = classifier.classify(make_event("CPU usage at 3748%", level=Level.WARN))
        assert impossible is None

    def test_keywords_and_rule_overrides(
        self, classifier: PatternClassifier, make_event: EventFactory
    ) -> None:
        oom = classifier.classify(make_event("java.lang.OutOfMemoryError: Java heap space"))
        assert oom is not None
        assert oom.kind == "memory_exhaustion"
        assert oom.severity is Severity.CRITICAL
        assert oom.min_occurrences == 1

    def test_generic_errors_and_unmatched_warnings(
        self, classifier: PatternClassifier, make_event: EventFactory
    ) -> None:
        generic = classifier.classify(make_event("Payment request failed", service="web-app"))
        assert generic is not None
        assert generic.source is SignalSource.GENERIC
        assert generic.category is Category.DEPENDENCY
        assert generic.targets == {"payment-service"}
        assert generic.fingerprint == ("error", "web-app", "Payment request failed")
        assert generic.is_weak
        app = classifier.classify(make_event("Something odd happened"))
        assert app is not None
        assert app.category is Category.APPLICATION
        fatal = classifier.classify(make_event("Something odd happened", level=Level.CRITICAL))
        assert fatal is not None
        assert fatal.severity is Severity.HIGH
        assert classifier.classify(make_event("Something odd", level=Level.WARN)) is None
        assert classifier.classify(make_event("Request processed in 5ms", level=Level.INFO)) is None

    def test_service_restricted_rules_and_explicit_captures(self, make_event: EventFactory) -> None:
        config = build_config({"patterns": [
            {"name": "card", "regex": r"declined code=(\w+) amount=(\d+)",
             "captures": ["code", "amount"], "group_by": ["service", "code"],
             "services": ["billing"], "severity": "HIGH", "category": "dependency",
             "target": "card-processor"},
        ]})
        classifier = PatternClassifier(config, ServiceDirectory(config))
        hit = classifier.classify(make_event("declined code=51 amount=20", service="billing"))
        assert hit is not None
        assert hit.fingerprint == ("card", "billing", "51")
        assert hit.attributes == {"code": "51", "amount": "20"}
        assert hit.targets == {"card-processor"}
        other = classifier.classify(make_event("declined code=51 amount=20", service="shop"))
        assert other is not None
        assert other.kind != "card"
