from __future__ import annotations

from typing import Any

import pytest

from log_analyzer.alerts.builder import AlertBuilder, humanize, title_case
from log_analyzer.config import AnalyzerConfig, build_config
from log_analyzer.correlation.correlator import AlertEventKind, Correlator
from log_analyzer.correlation.incident import Incident, IncidentStatus, self_evidence
from log_analyzer.correlation.rca import RootCauseAnalyzer
from log_analyzer.correlation.rules import RuleContext, RuleEngine
from log_analyzer.correlation.topology import ServiceDirectory
from log_analyzer.models import Category, Level, Severity, Signal, SignalSource
from log_analyzer.processing.classifier import PatternClassifier
from tests.conftest import TOPOLOGY, event

T0 = 1_704_880_800.0  # 2024-01-10T10:00:00Z


class Harness:
    """Feeds raw messages through the real classifier into a correlator."""

    def __init__(self, config: AnalyzerConfig, rate: float = 0.0) -> None:
        self.config = config
        self.directory = ServiceDirectory(config)
        self.classifier = PatternClassifier(config, self.directory)
        self.correlator = Correlator(config, self.directory, lambda _s, _n: rate)
        self.events: list[Any] = []

    def log(self, offset: float, service: str, message: str, level: Level = Level.ERROR) -> None:
        signal = self.classifier.classify(event(message, service=service, level=level,
                                                ts=T0 + offset, request_id=f"r{offset}"))
        assert signal is not None, message
        self.events.extend(self.correlator.ingest(signal))

    def signal(self, signal: Signal) -> None:
        self.events.extend(self.correlator.ingest(signal))

    def kinds(self) -> list[AlertEventKind]:
        return [e.kind for e in self.events]


def detector_signal(kind: str, service: str, offset: float, **attrs: Any) -> Signal:
    category = {"error_rate_spike": Category.AVAILABILITY, "resource_saturation": Category.RESOURCE,
                "latency_degradation": Category.PERFORMANCE}[kind]
    return Signal(kind=kind, source=SignalSource.DETECTOR, ts=T0 + offset, service=service,
                  severity=Severity.HIGH if kind != "latency_degradation" else Severity.MEDIUM,
                  category=category, fingerprint=(kind, service), template=f"{kind} {service}",
                  event=event("x", service=service, ts=T0 + offset), attributes=attrs)


@pytest.fixture
def config() -> AnalyzerConfig:
    return build_config(TOPOLOGY)


# ----------------------------------------------------------------------------- linking
def test_explicit_dependency_evidence_builds_one_cascade(config: AnalyzerConfig) -> None:
    h = Harness(config)
    h.log(0, "payment-provider", "Service health check failed: Connection refused")
    for i in range(3):
        h.log(1 + i, "payment-service", "Payment provider unavailable: connection refused")
    h.log(5, "order-service", "Cannot process order: payment service unavailable")
    h.log(6, "api-gateway", "Connection timeout to order-service after 30000ms")

    alerts = h.correlator.alerts()
    assert len(alerts) == 1
    incident, assessment = alerts[0]
    assert set(incident.services) == {
        "payment-provider", "payment-service", "order-service", "api-gateway"
    }
    assert assessment.cascade
    assert assessment.severity is Severity.CRITICAL
    assert assessment.root.service == "payment-provider"
    assert assessment.root.symptoms[0] == "payment-service"  # nearest dependent first
    assert h.kinds()[0] is AlertEventKind.NEW
    assert AlertEventKind.UPDATED in h.kinds()


def test_timeouts_are_backdated_into_the_cascade_window(config: AnalyzerConfig) -> None:
    h = Harness(config)
    h.log(0, "database", "Connection pool exhausted")
    h.log(0.5, "order-service", "Failed to acquire database connection: pool exhausted")
    h.log(1, "inventory-service", "Failed to acquire database connection: pool exhausted")
    # Logged 30.06 s after the last failure, but the call started at 0.06 s (30000 ms
    # timeout): it belongs to the chain. Without back-dating it would miss the 30 s window.
    h.log(30.06, "api-gateway", "Connection timeout to order-service after 30000ms")
    (incident,) = h.correlator.open_incidents()
    assert incident.cascade_members == [
        "database", "order-service", "inventory-service", "api-gateway"
    ]


def test_dependents_of_a_silent_dependency_do_not_link_through_it(
    config: AnalyzerConfig,
) -> None:
    """Random 'deadlock'/'too many connections' noise names the database from every
    service; linking through a dependency that never logs would snowball that noise."""
    h = Harness(config)
    h.log(0, "order-service", "Failed to acquire database connection: pool exhausted")
    h.log(1, "inventory-service", "Failed to acquire database connection: pool exhausted")
    assert len(h.correlator.open_incidents()) == 2


def test_random_noise_naming_services_does_not_link(config: AnalyzerConfig) -> None:
    h = Harness(config)
    h.log(0, "order-service", "Deadlock detected")
    h.log(1, "order-service", "Deadlock detected")
    # order-service does not depend on the gateway: an implausible claim is not evidence
    h.log(2, "order-service", "Failed to connect to api-gateway: timeout")
    h.log(3, "api-gateway", "Invalid request format")
    assert len(h.correlator.open_incidents()) >= 3
    assert not any(len(inc.services) > 1 for inc in h.correlator.open_incidents())


def test_same_error_must_repeat_within_the_grouping_window(config: AnalyzerConfig) -> None:
    h = Harness(config)
    for offset in (0, 50, 100, 150):  # every 50s: chained, but never 3 within 60s
        h.log(offset, "inventory-service", "Deadlock detected")
    assert h.correlator.alerts() == []
    h.log(160, "inventory-service", "Deadlock detected")
    h.log(170, "inventory-service", "Deadlock detected")
    assert len(h.correlator.alerts()) == 1


def test_low_severity_incidents_never_page(config: AnalyzerConfig) -> None:
    h = Harness(config)
    for i in range(10):
        h.log(i, "web-app", "Invalid request format", Level.WARN)
    assert h.correlator.alerts() == []


def test_critical_single_occurrence_rules_alert_immediately(config: AnalyzerConfig) -> None:
    h = Harness(config)
    h.log(0, "order-service", "java.lang.OutOfMemoryError: Java heap space")
    ((incident, assessment),) = h.correlator.alerts()
    assert assessment.severity is Severity.CRITICAL
    assert incident.alert is not None
    assert incident.alert.alert_id == "ALR-20240110-001"


def test_incidents_resolve_after_grouping_window(config: AnalyzerConfig) -> None:
    h = Harness(config)
    h.log(0, "order-service", "java.lang.OutOfMemoryError")
    h.events.extend(h.correlator.advance(T0 + 61))
    assert h.kinds()[-1] is AlertEventKind.RESOLVED
    ((incident, _),) = h.correlator.alerts()
    assert incident.status is IncidentStatus.RESOLVED
    assert incident.closed_at == T0 + 60
    assert h.correlator.open_incidents() == []


def test_unexplained_spikes_group_into_one_noise_alert_and_inhibit(config: AnalyzerConfig) -> None:
    h = Harness(config)
    for i, svc in enumerate(["order-service", "inventory-service", "web-app", "api-gateway"]):
        h.signal(detector_signal("error_rate_spike", svc, i, rate=50.0, baseline=0.1))
    alerts = h.correlator.alerts()
    assert len(alerts) == 1
    noise, assessment = alerts[0]
    assert noise.unexplained
    assert assessment.severity is Severity.MEDIUM  # broad, heterogeneous: capped
    assert assessment.root.confidence <= 0.3
    assert assessment.title == "Elevated Error Rate Across 4 Services"
    # A weak single-service incident now gets folded into the noise instead of paging.
    for i in range(3):
        h.log(10 + i, "order-service", "Deadlock detected")
    assert len(h.correlator.alerts()) == 1
    h.events.extend(h.correlator.advance(T0 + 2000))
    assert noise.services.keys() >= {"order-service"}
    assert h.correlator.stats.incidents_inhibited >= 1


def test_strong_incidents_are_not_absorbed_by_noise(config: AnalyzerConfig) -> None:
    h = Harness(config)
    for i, svc in enumerate(["order-service", "inventory-service", "web-app"]):
        h.signal(detector_signal("error_rate_spike", svc, i, rate=50.0, baseline=0.1))
    h.signal(detector_signal("resource_saturation", "database", 5, utilization_pct=96.0,
                             level="critical"))
    titles = {a.title for _, a in h.correlator.alerts()}
    assert len(titles) == 2


def test_detector_condition_reopens_within_cooldown(config: AnalyzerConfig) -> None:
    h = Harness(config)
    h.signal(detector_signal("resource_saturation", "database", 0, utilization_pct=96.0))
    h.events.extend(h.correlator.advance(T0 + 100))
    h.signal(detector_signal("resource_saturation", "database", 200, utilization_pct=97.0))
    assert h.kinds() == [AlertEventKind.NEW, AlertEventKind.RESOLVED, AlertEventKind.REOPENED]
    assert len(h.correlator.alerts()) == 1
    assert h.correlator.stats.reopened == 1


def test_bridging_signal_merges_incidents(config: AnalyzerConfig) -> None:
    h = Harness(config)
    h.log(0, "api-gateway", "Connection timeout to order-service after 5000ms")
    h.log(1, "order-service", "Invalid request format")  # application-level: no link
    assert len(h.correlator.open_incidents()) == 2
    # A repeat of the gateway timeout matches incident 1 by fingerprint and names
    # order-service, which is in incident 2: the two are merged.
    h.log(2, "api-gateway", "Connection timeout to order-service after 5000ms")
    (incident,) = h.correlator.open_incidents()
    assert set(incident.services) == {"api-gateway", "order-service"}
    assert h.correlator.stats.incidents_merged == 1


def test_open_incident_cap_bounds_memory() -> None:
    config = build_config({**TOPOLOGY, "limits": {"max_open_incidents": 3}})
    h = Harness(config)
    for i in range(10):
        h.log(i, f"svc-{i}", "Something odd happened")
    assert len(h.correlator.open_incidents()) <= 3


# ---------------------------------------------------------------------------------- RCA
def _incident(config: AnalyzerConfig, signals: list[Signal]) -> Incident:
    incident = Incident(signals[0], config.limits, 30.0)
    for s in signals[1:]:
        incident.add(s)
    return incident


def _sig(service: str, offset: float, category: Category, targets: frozenset[str] = frozenset(),
         level: Level = Level.ERROR) -> Signal:
    return Signal(kind=f"k-{category.value}", source=SignalSource.PATTERN, ts=T0 + offset,
                  service=service, severity=Severity.HIGH, category=category,
                  fingerprint=(service, category.value), template="t", targets=targets,
                  event=event("m", service=service, level=level, ts=T0 + offset))


def test_rca_prefers_the_deepest_self_reporting_dependency(config: AnalyzerConfig) -> None:
    incident = _incident(config, [
        _sig("api-gateway", 2, Category.DEPENDENCY, frozenset({"order-service"})),
        _sig("order-service", 1, Category.DEPENDENCY, frozenset({"database"})),
        _sig("database", 0, Category.RESOURCE),
    ])
    rca = RootCauseAnalyzer(ServiceDirectory(config), config.correlation.rca_weights)
    root = rca.analyze(incident)
    assert root.service == "database"
    assert not root.inferred
    assert root.symptoms == ("order-service", "api-gateway")
    assert root.confidence >= 0.9


def test_rca_infers_a_silent_dependency(config: AnalyzerConfig) -> None:
    incident = _incident(config, [
        _sig("payment-service", 0, Category.DEPENDENCY, frozenset({"payment-provider"})),
        _sig("order-service", 1, Category.DEPENDENCY, frozenset({"payment-service"})),
    ])
    root = RootCauseAnalyzer(ServiceDirectory(config), config.correlation.rca_weights).analyze(
        incident)
    assert root.service == "payment-provider"
    assert root.inferred


def test_rca_single_service_and_unexplained(config: AnalyzerConfig) -> None:
    rca = RootCauseAnalyzer(ServiceDirectory(config), config.correlation.rca_weights)
    single = _incident(config, [_sig("web-app", 0, Category.RESOURCE)])
    assert rca.analyze(single).service == "web-app"
    assert rca.analyze(single).confidence == pytest.approx(0.9)
    noise = Incident(_sig("a", 0, Category.APPLICATION), config.limits, 30.0, unexplained=True)
    noise.add(_sig("b", 1, Category.APPLICATION))
    assert rca.analyze(noise).confidence == 0.25


def test_self_evidence_scale() -> None:
    assert self_evidence(_sig("db", 0, Category.RESOURCE)) == 1.0
    assert self_evidence(_sig("x", 0, Category.DEPENDENCY, frozenset({"db"}))) == 0.1
    assert self_evidence(_sig("x", 0, Category.PERFORMANCE)) == 0.7
    assert self_evidence(_sig("x", 0, Category.DEPENDENCY)) == 0.2
    assert self_evidence(_sig("x", 0, Category.APPLICATION)) == 0.3


# -------------------------------------------------------------------------------- rules
def test_rule_engine_predicates(config: AnalyzerConfig) -> None:
    rules = build_config({**TOPOLOGY, "alert_rules": [
        {"name": "focus", "severity": "HIGH", "condition": {"all": [
            {"service": "api-gateway"}, {"error_rate": ">5%"}, {"duration": ">=2s"}]}},
        {"name": "any", "severity": "LOW", "condition": {"any": [
            {"root_cause": "nope"}, {"category": "cascade"}, {"error_count": ">=2"}]}},
        {"name": "pattern", "severity": "LOW", "condition": {"all": [
            {"pattern": "(?i)timeout"}, {"unique_errors": ">=1"}, {"severity": ">=HIGH"},
            {"cascade": False}, {"affected_services": "2"}]}},
    ]}).alert_rules
    incident = _incident(config, [
        _sig("api-gateway", 0, Category.DEPENDENCY, frozenset({"order-service"})),
        _sig("order-service", 3, Category.RESOURCE),
    ])
    incident.templates["Connection timeout to order-service"] += 1
    rates = {"api-gateway": 12.0, "order-service": 1.0}
    ctx = RuleContext(incident=incident, root_cause="order-service", category="resource",
                      cascade=False, severity=Severity.HIGH, error_rate=lambda s: rates[s])
    names = {r.name for r in RuleEngine(rules).matching(ctx)}
    assert {"focus", "any", "pattern"} <= names
    rates["api-gateway"] = 1.0
    assert "focus" not in {r.name for r in RuleEngine(rules).matching(ctx)}


# ------------------------------------------------------------------------------ builder
def test_humanize_and_title_case() -> None:
    assert humanize("api-gateway") == "API Gateway"
    assert humanize("payment_service") == "Payment Service"
    assert title_case("database query time") == "Database Query Time"


def test_alert_dict_follows_the_spec_format(config: AnalyzerConfig) -> None:
    h = Harness(config)
    h.log(0, "payment-provider", "Service health check failed: Connection refused")
    for i in range(3):
        h.log(1 + i, "payment-service", "Payment provider unavailable: connection refused")
    h.log(5, "order-service", "Cannot process order: payment service unavailable")
    ((incident, assessment),) = h.correlator.alerts()
    view = AlertBuilder(config).build(incident, assessment)
    data = view.to_dict()
    assert list(data)[:10] == [
        "alert_id", "severity", "title", "summary", "timeline", "impact",
        "root_cause_analysis", "suggested_actions", "sample_logs", "deduplication_stats",
    ]
    assert data["timeline"]["total_duration_seconds"] == 5
    assert data["impact"]["error_count"] == 5
    assert data["impact"]["estimated_failed_requests"] == 5  # distinct request ids
    stats = data["deduplication_stats"]
    assert stats["total_logs_analyzed"] == 5
    assert stats["logs_grouped"] == stats["total_logs_analyzed"] - data["impact"]["unique_errors"]
    assert data["root_cause_analysis"]["evidence"]
    assert data["sample_logs"][0].startswith("ERROR [payment-provider]")  # root first
    assert data["suggested_actions"][0].startswith("1. ")
    assert data["cascading_failure"] is True
    assert data["status"] == "active"
    with pytest.raises(ValueError, match="has not alerted"):
        AlertBuilder(config).build(Incident(_sig("x", 0, Category.RESOURCE), config.limits, 30.0),
                                   assessment)
