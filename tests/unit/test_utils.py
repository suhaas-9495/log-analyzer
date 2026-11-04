from __future__ import annotations

import pytest

from log_analyzer.models import Category, Level, Severity
from log_analyzer.plugins import PluginError, Registry, load_reference
from log_analyzer.stats import kendall_tau, kendall_z, median, percentile, slope
from log_analyzer.timeutil import (
    format_clock,
    format_date_compact,
    format_datetime,
    format_duration,
    format_iso,
    parse_duration,
    parse_timestamp,
)

T0 = 1704880800.0  # 2024-01-10T10:00:00Z


class TestTimeutil:
    @pytest.mark.parametrize(
        ("text", "expected"),
        [
            ("2024-01-10 10:00:00", T0),
            ("2024-01-10T10:00:00Z", T0),
            ("2024-01-10 10:00:00.250", T0 + 0.25),
            ("2024-01-10 10:00:00,250", T0 + 0.25),
            ("2024-01-10T10:00:00.250000123Z", T0 + 0.25),
            ("2024-01-10T15:30:00+05:30", T0),
        ],
    )
    def test_parse_timestamp(self, text: str, expected: float) -> None:
        assert parse_timestamp(text) == pytest.approx(expected)

    @pytest.mark.parametrize("text", ["yesterday", "2024-13-01 00:00:00", "", "2024-01-10 25:00"])
    def test_parse_timestamp_rejects_garbage(self, text: str) -> None:
        with pytest.raises(ValueError):  # noqa: PT011 - ValueError subclasses vary by input
            parse_timestamp(text)

    def test_formatting(self) -> None:
        assert format_iso(T0) == "2024-01-10T10:00:00Z"
        assert format_datetime(T0) == "2024-01-10 10:00:00"
        assert format_clock(T0 + 65) == "10:01:05"
        assert format_date_compact(T0) == "20240110"
        assert format_duration(277) == "4m 37s"
        assert format_duration(3725) == "1h 02m"
        assert format_duration(12.4) == "12s"
        assert format_duration(-5) == "0s"

    @pytest.mark.parametrize(
        ("value", "seconds"),
        [
            ("5m", 300),
            ("300s", 300),
            ("1.5h", 5400),
            ("250ms", 0.25),
            (60, 60),
            ("90", 90),
            ("2 min", 120),
            ("1d", 86400),
        ],
    )
    def test_parse_duration(self, value: str | float, seconds: float) -> None:
        assert parse_duration(value) == pytest.approx(seconds)

    @pytest.mark.parametrize("value", ["soon", "-5m", "0", 0, True, "5 parsecs"])
    def test_parse_duration_rejects(self, value: str | float) -> None:
        with pytest.raises(ValueError, match="duration"):
            parse_duration(value)


class TestStats:
    def test_median_and_percentile(self) -> None:
        assert median([3, 1, 2]) == 2
        assert median([4, 1, 3, 2]) == 2.5
        assert percentile(list(range(1, 101)), 95) == 95
        assert percentile([7], 99) == 7
        with pytest.raises(ValueError, match="empty"):
            median([])
        with pytest.raises(ValueError, match="empty"):
            percentile([], 50)

    def test_kendall(self) -> None:
        assert kendall_tau([1, 2, 3, 4]) == 1.0
        assert kendall_tau([4, 3, 2, 1]) == -1.0
        assert kendall_tau([1]) == 0.0
        assert kendall_tau([5, 5, 5]) == 0.0
        # Spec Scenario 2: five strictly increasing samples are significant at z ~ 2.45
        assert kendall_z(1.0, 5) == pytest.approx(2.449, abs=1e-3)
        assert kendall_z(1.0, 2) == 0.0

    def test_slope(self) -> None:
        assert slope([(0, 0), (1, 2), (2, 4)]) == pytest.approx(2.0)
        assert slope([(1, 5)]) == 0.0
        assert slope([(1, 5), (1, 6)]) == 0.0


class TestModels:
    @pytest.mark.parametrize(
        ("raw", "level"),
        [
            ("warning", Level.WARN),
            ("FATAL", Level.CRITICAL),
            (" err ", Level.ERROR),
            ("trace", Level.DEBUG),
            ("notice", Level.INFO),
        ],
    )
    def test_level_aliases(self, raw: str, level: Level) -> None:
        assert Level.parse(raw) is level

    def test_parse_errors(self) -> None:
        with pytest.raises(ValueError, match="unknown log level"):
            Level.parse("LOUD")
        with pytest.raises(ValueError, match="unknown severity"):
            Severity.parse("URGENT")
        with pytest.raises(ValueError, match="unknown category"):
            Category.parse("weird")
        assert Severity.parse("high") is Severity.HIGH
        assert max(Severity.LOW, Severity.CRITICAL) is Severity.CRITICAL


class TestPlugins:
    def test_registry_and_references(self) -> None:
        registry: Registry[int] = Registry("thing")
        registry.register("a")(1)
        assert registry.get("a") == 1
        assert registry.names() == ["a"]
        with pytest.raises(PluginError, match="unknown thing"):
            registry.get("b")
        assert load_reference("tests.unit.plugin_examples:NOT_CALLABLE") == 42
        for bad in ("no-colon", ":x", "x:", "nope.module:X", "tests.unit.plugin_examples:Nope"):
            with pytest.raises(PluginError):
                load_reference(bad)
