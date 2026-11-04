"""Robustness sweep: run the analyzer on N generated datasets with different seeds.

For each seed, checks that every injected incident is detected with the right root cause
and counts any additional alerts. Used to validate tuning against random data rather than
only the provided samples.

    python scripts/robustness.py --seeds 10 --lines 50000
"""

from __future__ import annotations

import argparse
import io
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from log_analyzer.config import load_config  # noqa: E402
from log_analyzer.engine import Analyzer  # noqa: E402
from log_analyzer.testdata.generator import GeneratorSettings, generate  # noqa: E402

EXPECTED = {
    "pool exhaustion (CRITICAL, root database)": lambda a: a.severity.name == "CRITICAL"
    and a.root_service == "database",
    "payment cascade (CRITICAL, root payment-provider)": lambda a: a.severity.name == "CRITICAL"
    and a.root_service == "payment-provider",
    "perf degradation (MEDIUM, root database)": lambda a: a.category == "performance"
    and a.root_service == "database",
}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--seeds", type=int, default=10)
    parser.add_argument("--lines", type=int, default=50_000)
    parser.add_argument("--config", default="configs/config.yaml")
    args = parser.parse_args()
    config = load_config(args.config)
    missed = extra_total = 0
    for seed in range(1, args.seeds + 1):
        buffer = io.StringIO()
        generate(GeneratorSettings(lines=args.lines, seed=seed), buffer)
        analyzer = Analyzer(config)
        started = time.perf_counter()
        for line in buffer.getvalue().splitlines():
            analyzer.process_line(line)
        result = analyzer.result()
        elapsed = time.perf_counter() - started
        found = {name: any(check(a) for a in result.alerts) for name, check in EXPECTED.items()}
        expected_like = sum(1 for a in result.alerts if any(c(a) for c in EXPECTED.values()))
        noise_alerts = sum(1 for a in result.alerts if a.category in ("error_rate", "errors"))
        extra = len(result.alerts) - expected_like - noise_alerts
        missed += sum(1 for ok in found.values() if not ok)
        extra_total += max(0, extra)
        status = "ok" if all(found.values()) else "MISSED " + ", ".join(
            n for n, ok in found.items() if not ok
        )
        print(
            f"seed {seed:>3}: {len(result.alerts)} alerts ({noise_alerts} noise, {extra} other) "
            f"noise reduction {result.noise_reduction:.1f}% in {elapsed:.2f}s - {status}"
        )
    print(f"\nmissed incidents: {missed}, extra alerts: {extra_total} over {args.seeds} datasets")
    return 1 if missed else 0


if __name__ == "__main__":
    raise SystemExit(main())
