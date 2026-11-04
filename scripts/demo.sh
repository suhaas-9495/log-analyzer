#!/usr/bin/env bash
# End-to-end demo of the analyzer. Run with `make demo` (or `bash scripts/demo.sh` with
# `log-analyzer` on PATH). Every step uses only the public CLI / HTTP API.
set -euo pipefail
cd "$(dirname "$0")/.."
CONFIG=configs/config.yaml
OUT=$(mktemp -d)
trap 'rm -rf "$OUT"; [[ -n "${API_PID:-}" ]] && kill "$API_PID" 2>/dev/null || true' EXIT

step() { printf '\n\033[1;34m==> %s\033[0m\n' "$*"; }

step "1. Spec Scenario 1 - cascade failure (expect ONE critical alert, root cause: database)"
log-analyzer --file tests/fixtures/scenario1_cascade.log --config "$CONFIG" --events

step "2. Spec Scenario 2 - gradual degradation (expect MEDIUM alert before the 1000ms timeout)"
log-analyzer --file tests/fixtures/scenario2_degradation.log --config "$CONFIG" --events \
  | head -n 4

step "3. Spec Scenario 3 - dev noise is ignored, production issue alerts"
log-analyzer --file tests/fixtures/scenario3_dev_noise.log --config "$CONFIG" --format json \
  | python3 -c 'import json,sys; r=json.load(sys.stdin); s=r["statistics"]; print(f"ignored={s[\"logs_ignored\"]} alerts={[a[\"title\"] for a in r[\"alerts\"]]}")'

step "4. Live stream (stdin): the 10k sample piped in, alerts printed as they happen"
cat data/sample/test_logs.txt | log-analyzer --config "$CONFIG" --color never \
  | grep -E '^\[[0-9:]+\] (NEW|RESOLVED)'

step "5. Batch dashboard for the provided 10k-line sample"
log-analyzer --file data/sample/test_logs.txt --config "$CONFIG"

step "6. JSON output for integrations (first alert, abridged)"
log-analyzer --file data/sample/test_logs.txt --config "$CONFIG" --format json -o "$OUT/report.json"
python3 - "$OUT/report.json" <<'PY'
import json, sys
report = json.load(open(sys.argv[1]))
alert = next(a for a in report["alerts"] if a["severity"] == "CRITICAL")
keep = ["alert_id", "severity", "title", "summary", "timeline", "impact",
        "root_cause_analysis", "suggested_actions", "deduplication_stats"]
print(json.dumps({k: alert[k] for k in keep}, indent=2))
print("statistics:", report["statistics"]["total_logs"], "logs,",
      report["statistics"]["alerts_generated"], "alerts,",
      f'{report["statistics"]["noise_reduction_percent"]}% noise reduction')
PY

step "7. Scenario 4 - 100,000 generated lines (time and memory)"
log-analyzer generate --lines 100000 --seed 42 -o "$OUT/100k.log"
log-analyzer --file "$OUT/100k.log" --config "$CONFIG" --format json \
  | python3 -c 'import json,sys; r=json.load(sys.stdin); m=r["metrics"]; s=r["statistics"]; print(f"{s[\"total_logs\"]:,} lines in {m[\"processing_time_ms\"]} ms, peak {m[\"memory_usage_mb\"]} MB, {s[\"alerts_generated\"]} alerts, {s[\"noise_reduction_percent\"]}% noise reduction")'

step "8. HTTP API: POST /analyze"
PORT=${PORT:-18080}
log-analyzer serve --config "$CONFIG" --host 127.0.0.1 --port "$PORT" & API_PID=$!
for _ in $(seq 1 50); do curl -fs "http://127.0.0.1:$PORT/health" >/dev/null 2>&1 && break; sleep 0.1; done
python3 - "$PORT" <<'PY'
import json, sys, urllib.request
lines = open("tests/fixtures/scenario1_cascade.log").read().splitlines()
req = urllib.request.Request(f"http://127.0.0.1:{sys.argv[1]}/analyze",
                             data=json.dumps({"logs": lines, "window": "5m"}).encode(),
                             headers={"Content-Type": "application/json"})
report = json.load(urllib.request.urlopen(req))
a = report["alerts"][0]
print(f'{a["alert_id"]} [{a["severity"]}] {a["title"]} -> root cause {a["root_cause_service"]} '
      f'({a["root_cause_analysis"]["confidence"]:.0%})')
PY
step "Done."
