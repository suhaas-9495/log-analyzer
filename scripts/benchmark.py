"""Throughput and memory benchmark.

Generates datasets of increasing size and analyzes each in a *fresh* process (so peak RSS
is measured for one run only), printing a Markdown table.

    python scripts/benchmark.py --lines 100000          # 10k, 100k
    python scripts/benchmark.py --lines 1000000         # 10k, 100k, 1M
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from log_analyzer.testdata.generator import GeneratorSettings, generate  # noqa: E402


def run(path: Path, config: Path) -> dict[str, float]:
    started = time.perf_counter()
    completed = subprocess.run(
        [
            sys.executable,
            "-m",
            "log_analyzer",
            "--file",
            str(path),
            "--config",
            str(config),
            "--format",
            "json",
        ],
        capture_output=True,
        text=True,
        check=True,
    )
    wall = time.perf_counter() - started
    report = json.loads(completed.stdout)
    return {
        "lines": report["statistics"]["total_logs"],
        "wall_s": wall,
        "processing_s": report["metrics"]["processing_time_ms"] / 1000,
        "lines_per_s": report["metrics"]["lines_per_second"],
        "memory_mb": report["metrics"]["memory_usage_mb"],
        "alerts": report["statistics"]["alerts_generated"],
        "noise": report["statistics"]["noise_reduction_percent"],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--lines", type=int, default=100_000, help="largest dataset size")
    parser.add_argument("--config", type=Path, default=ROOT / "configs" / "config.yaml")
    args = parser.parse_args()
    sizes = [n for n in (10_000, 100_000, 1_000_000, 10_000_000) if n <= args.lines] or [args.lines]
    columns = [
        "Lines",
        "Processing",
        "Wall (incl. start-up)",
        "Throughput",
        "Peak memory",
        "Alerts",
        "Noise reduction",
    ]
    print("| " + " | ".join(columns) + " |")
    print("|" + "---:|" * len(columns))
    with tempfile.TemporaryDirectory() as tmp:
        for size in sizes:
            path = Path(tmp) / f"bench_{size}.log"
            with path.open("w", encoding="utf-8") as handle:
                generate(GeneratorSettings(lines=size, seed=42), handle)
            r = run(path, args.config)
            print(
                f"| {r['lines']:,.0f} | {r['processing_s']:.2f} s | {r['wall_s']:.2f} s | "
                f"{r['lines_per_s']:,.0f} lines/s | {r['memory_mb']:.1f} MB | {r['alerts']:.0f} | "
                f"{r['noise']:.1f}% |"
            )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
