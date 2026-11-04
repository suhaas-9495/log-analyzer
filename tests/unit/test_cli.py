from __future__ import annotations

import gzip
import io
import json
from pathlib import Path

import pytest

from log_analyzer import __version__, cli
from tests.conftest import CONFIG_PATH, FIXTURES

SCENARIO1 = str(FIXTURES / "scenario1_cascade.log")


def run(capsys: pytest.CaptureFixture[str], *args: str) -> tuple[int, str, str]:
    code = cli.main(list(args))
    out, err = capsys.readouterr()
    return code, out, err


def test_file_to_console_dashboard(capsys: pytest.CaptureFixture[str]) -> None:
    code, out, _ = run(
        capsys, "--file", SCENARIO1, "--config", str(CONFIG_PATH), "--color", "never"
    )
    assert code == 0
    assert "LOG ANALYSIS DASHBOARD" in out
    assert "[CRITICAL] Database Connection Crisis" in out


def test_events_flag_prints_lifecycle(capsys: pytest.CaptureFixture[str]) -> None:
    code, out, _ = run(
        capsys, "-f", SCENARIO1, "-c", str(CONFIG_PATH), "--events", "--color", "never"
    )
    assert code == 0
    assert "NEW" in out.splitlines()[0]


def test_json_report_to_file(capsys: pytest.CaptureFixture[str], tmp_path: Path) -> None:
    target = tmp_path / "report.json"
    code, out, _ = run(
        capsys, "-f", SCENARIO1, "-c", str(CONFIG_PATH), "--format", "json", "-o", str(target)
    )
    assert code == 0
    assert out == ""
    report = json.loads(target.read_text())
    assert report["statistics"]["alerts_generated"] == 1


def test_console_report_to_file_is_plain(
    capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    target = tmp_path / "dashboard.txt"
    run(capsys, "-f", SCENARIO1, "-c", str(CONFIG_PATH), "--color", "always", "-o", str(target))
    text = target.read_text()
    assert "LOG ANALYSIS DASHBOARD" in text
    assert "\033[" not in text


def test_jsonl_streams_events_then_summary(capsys: pytest.CaptureFixture[str]) -> None:
    code, out, _ = run(capsys, "-f", SCENARIO1, "-c", str(CONFIG_PATH), "--format", "jsonl")
    assert code == 0
    records = [json.loads(line) for line in out.strip().splitlines()]
    assert records[0]["event"] == "NEW"
    assert records[-1]["event"] == "SUMMARY"
    assert records[-1]["report"]["statistics"]["alerts_generated"] == 1


def test_window_and_fail_on(capsys: pytest.CaptureFixture[str]) -> None:
    code, out, _ = run(
        capsys,
        "-f",
        SCENARIO1,
        "-c",
        str(CONFIG_PATH),
        "--format",
        "json",
        "--window",
        "30s",
        "--fail-on",
        "HIGH",
    )
    assert code == cli.EXIT_ALERTS
    assert json.loads(out)["analysis_period"]["start"] == "2024-01-10T10:00:47Z"
    code, _, _ = run(
        capsys,
        "-f",
        str(FIXTURES / "scenario2_degradation.log"),
        "-c",
        str(CONFIG_PATH),
        "--fail-on",
        "CRITICAL",
        "--color",
        "never",
    )
    assert code == 0


def test_multiple_files_are_merged_by_time(
    capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    lines = Path(SCENARIO1).read_text().splitlines()
    first = tmp_path / "db.log"
    second = tmp_path / "apps.log.gz"
    first.write_text("\n".join(lines[:3]) + "\n")
    with gzip.open(second, "wt", encoding="utf-8") as handle:
        handle.write("\n".join(lines[3:]) + "\n")
    code, out, _ = run(
        capsys, "-f", str(second), "-f", str(first), "-c", str(CONFIG_PATH), "--format", "json"
    )
    assert code == 0
    report = json.loads(out)
    assert report["statistics"]["total_logs"] == 7
    assert report["alerts"][0]["root_cause_service"] == "database"


def test_stdin_stream(capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("sys.stdin", io.StringIO(Path(SCENARIO1).read_text()))
    code, out, _ = run(capsys, "--config", str(CONFIG_PATH), "--color", "never")
    assert code == 0
    assert "NEW" in out  # live events are printed while streaming
    assert "LOG ANALYSIS DASHBOARD" in out


def test_stdin_dash_and_conflicts(
    capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("sys.stdin", io.StringIO(Path(SCENARIO1).read_text()))
    code, out, _ = run(capsys, "-f", "-", "-c", str(CONFIG_PATH), "--format", "json")
    assert code == 0
    assert json.loads(out)["statistics"]["total_logs"] == 7
    code, _, err = run(capsys, "-f", "-", "-f", SCENARIO1)
    assert code == cli.EXIT_USAGE
    assert "cannot combine" in err


def test_no_input_on_a_terminal(
    capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    class Tty(io.StringIO):
        def isatty(self) -> bool:
            return True

    monkeypatch.setattr("sys.stdin", Tty())
    code, _, err = run(capsys)
    assert code == cli.EXIT_USAGE
    assert "no input" in err


def test_errors_are_reported_cleanly(capsys: pytest.CaptureFixture[str], tmp_path: Path) -> None:
    code, _, err = run(capsys, "-f", str(tmp_path / "missing.log"))
    assert code == cli.EXIT_ERROR
    assert "error:" in err
    bad = tmp_path / "bad.yaml"
    bad.write_text("thresholds: {min_occurrences: 0}")
    code, _, err = run(capsys, "-f", SCENARIO1, "-c", str(bad))
    assert code == cli.EXIT_ERROR
    assert "configuration error: thresholds.min_occurrences" in err
    code, _, err = run(capsys, "-f", SCENARIO1, "--window", "soon")
    assert code == cli.EXIT_ERROR
    with pytest.raises(SystemExit):
        cli.main(["--format", "xml"])


def test_config_from_environment(
    capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv(cli.CONFIG_ENV, str(CONFIG_PATH))
    code, out, _ = run(capsys, "-f", SCENARIO1, "--format", "json")
    assert code == 0
    assert json.loads(out)["alerts"][0]["title"] == "Database Connection Crisis"


def test_validate_config(capsys: pytest.CaptureFixture[str], tmp_path: Path) -> None:
    code, out, _ = run(capsys, "validate-config", "--config", str(CONFIG_PATH))
    assert code == 0
    assert out.startswith("OK:")
    bad = tmp_path / "bad.yaml"
    bad.write_text("nonsense: true")
    code, _, err = run(capsys, "validate-config", "--config", str(bad))
    assert code == cli.EXIT_ERROR
    assert "unknown section" in err


def test_generate(capsys: pytest.CaptureFixture[str], tmp_path: Path) -> None:
    target = tmp_path / "out" / "gen.log"
    code, _, err = run(capsys, "generate", "--lines", "500", "--seed", "3", "-o", str(target))
    assert code == 0
    assert "wrote" in err
    assert len(target.read_text().splitlines()) >= 450
    code, out, _ = run(capsys, "generate", "--lines", "100", "--scenarios", "payment_cascade")
    assert code == 0
    assert "payment-provider" in out
    with pytest.raises(SystemExit):
        cli.main(["generate", "--scenarios", "alien_invasion"])


def test_version(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as info:
        cli.main(["--version"])
    assert info.value.code == 0
    assert __version__ in capsys.readouterr().out


def test_broken_pipe_exits_quietly(monkeypatch: pytest.MonkeyPatch) -> None:
    def boom(_argv: list[str]) -> int:
        raise BrokenPipeError

    monkeypatch.setattr(cli, "_analyze", boom)
    monkeypatch.setattr("os.dup2", lambda *_args: None)
    assert cli.main(["-f", SCENARIO1]) == 0


def test_opentelemetry_logs_give_the_same_alert_as_text(
    capsys: pytest.CaptureFixture[str],
) -> None:
    # Scenario 1 as OTLP/JSON: three single records, then one Collector export batch
    # holding the four error records from four services.
    otel = str(FIXTURES / "scenario1_cascade_otel.jsonl")
    code, out, _ = run(capsys, "-f", otel, "-c", str(CONFIG_PATH), "--format", "json")
    assert code == 0
    report = json.loads(out)
    assert report["statistics"]["formats"] == {"otel": 7}
    assert report["statistics"]["total_logs"] == 7  # records, not the 4 physical lines
    (alert,) = report["alerts"]
    assert alert["severity"] == "CRITICAL"
    assert alert["title"] == "Database Connection Crisis"
    assert alert["root_cause_service"] == "database"
    assert alert["impact"]["estimated_failed_requests"] == 1  # all four share one trace
