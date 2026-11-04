# Design

This document explains how the analyzer works, **how the design was arrived at**, what
was traded off, and how it would scale to a production environment with millions of
logs per minute.

1. [Goals and constraints](#1-goals-and-constraints)
2. [How the design was arrived at](#2-how-the-design-was-arrived-at)
3. [Architecture](#3-architecture)
4. [Stage by stage](#4-stage-by-stage)
5. [Correlation, root cause and noise](#5-correlation-root-cause-and-noise)
6. [Alert model](#6-alert-model)
7. [Time, streaming and memory](#7-time-streaming-and-memory)
8. [Performance](#8-performance)
9. [Validation](#9-validation)
10. [Trade-offs and alternatives](#10-trade-offs-and-alternatives)
11. [Scaling to millions of logs per minute](#11-scaling-to-millions-of-logs-per-minute)
12. [Future work](#12-future-work)

---

## 1. Goals and constraints

The problem statement frames this as an on-call problem: *847 alerts across 23 services
for one database pool exhaustion*. The goal is not to find every error but to **page
once, for the right thing, with enough context to act**.

**Hard requirements**
- Parse text, JSON and app-specific logs.
- Detect error-rate spikes against a configurable threshold.
- Group related errors with more than 80% noise reduction (more than 95% at 100k lines).
- Unit tests with more than 70% coverage.
- YAML configuration.
- File and stdin input; console and JSON output.
- Process 100k lines in under 5 s and 100 MB.

**Design considerations named in the spec**
- Streaming and batch.
- Memory bounded by sliding windows.
- Regexes compiled once.
- Service state tracked across windows.
- A plugin architecture.

**What "production quality" means here**
- No hard-coded rules; behaviour is driven by configuration.
- Configuration is validated.
- Errors are handled and malformed input is survived.
- Lint and strict typing.
- A reproducible build and container.

## 2. How the design was arrived at

The design was driven by the **data first, the spec second**. Before writing any detection
logic I profiled both sample files: formats, levels, services, message templates, value
distributions, and per-minute error counts.

### 2.1 What the data revealed

| Finding in the sample data | Consequence for the design |
|---|---|
| The three formats are **interleaved line by line** | Format detection per line, not per file. A first-character dispatch makes it cheap. |
| The Monolog lines (`[ts] production.ERROR: …`) have **no service field**; the useful detail sits in a trailing JSON context | Channel-to-service mapping in config; context parsed into fields but kept in the message so rules can match it. |
| Numeric fields are **deliberately garbled**: `Request processed in ord_78642ms`, `CPU usage at 3748%`, `Connection timeout to file_007f1c1f.txt after user-servicems` | Regexes require real digits; `value_range` on percentages; dependency targets must resolve to *known* services. None of these may crash or alert. |
| The **performance degradation never crosses 1000 ms** (latency 115 → 440 ms, queries 58 → 308 ms) | A threshold-only detector would miss it, so a **trend** detector is needed. It is also what "alert before failure" means. |
| The pool exhaustion is preceded by a **visible climb** from 50% to 88% (INFO), then 90–98% (WARN) | A utilization gauge with time-to-exhaustion, which alerts 41 s before the pool runs out. |
| api-gateway's timeouts arrive **30.06 s** after the failure they report, because the client timeout is 30000 ms | A strict 30 s cascade window splits the incident by milliseconds, so **timeouts are back-dated by their duration**. |
| Two long **bands of random errors** across all ten services, and the random messages **name real services** ("order-service: api-gateway connection attempt timed out") | The biggest trap. See §2.2. |
| DEBUG logs from `dev-server`, `localhost`, `test-runner`, `debug-console`; the spec's `DEBUG.*development` ignore rule does not match them | Level and service-glob filters in addition to the spec's ignore regexes. |
| The spec's sample rule `Query took (\d+)ms` does not match the data (`Slow query detected: 4564ms`, `execution_time_ms`) | A rule library written against real formats; rules can read structured fields; the spec's own shape is still accepted. |

### 2.2 Iterations on correlation, the hard part

Each step below was driven by running the analyzer on both samples and reading every
alert it produced.

1. **Time proximity**, roughly the spec's `multiple_services_failing_within_30_seconds`.
   - Result: the noise bands produced **CRITICAL "cascades"**, because in a 13-minute band of random errors three services always fail within 30 s of each other.
   - Lesson: time alone is not evidence.
2. **Explicit evidence plus static dependencies.** Link failures when a log names the dependency, or when the config says A depends on B.
   - Result: still fake cascades. The API gateway depends on everything, so any gateway error linked to any failing service. Noise snowballed through the hub.
   - Lesson: static edges must not link *failures*.
3. **Evidence only.**
   - Result: still noise. The random messages *name real services*, so they look like evidence.
   - Observation: in every real incident in the data, the claimed edge **agrees with the topology** (order→database, gateway→order, payment→provider, web-app→payment). Most noise claims don't (order-service "failing to connect to" the API gateway that calls it).
   - Change: claimed edges are **validated against configured dependencies**. Services with no configured topology still trust their logs.
4. **A noise bucket.** Even valid claims occasionally line up by chance inside a noise band, for example the gateway timing out on a service that happens to log a DB error.
   - Change: error-rate spikes that no incident explains are gathered into one "elevated error rate, no common root cause" alert. While that alert is active and broad, *weak* incidents fold into it instead of paging, as with Alertmanager inhibition.
   - Guard: *strong* incidents always page. Strong means backed by a metric detector, or with a self-reporting, corroborated root.
5. **Robustness on random data.** Tuning on two files risks overfitting, so I added a deterministic generator and a sweep over random seeds (§9). That exposed two more issues, both fixed:
   - The noise alert flapped open and closed between sparse spikes; fixed with a hold window.
   - A sparse latency trend (5 samples, as in spec Scenario 2) can occur by chance about 1 time in 120; such trends now count as strong only outside broad noise.

## 3. Architecture

```
                 ┌──────────────────────────────────────────────────────────────────┐
  file(s) ──┐    │ Analyzer (engine.py)                                             │
  .gz       │    │                                                                  │
  stdin  ───┼──► │  ParserChain ─► EventFilter ─► PatternClassifier ─► Signal       │
  HTTP   ───┘    │  text│json│app   level, dev     rule library (YAML)    (per line) │
                 │  + plugins       services,     MetricExtractor ─┐                 │
                 │                  ignore regex  latency, pools   │                 │
                 │                                                 ▼                 │
                 │                     Detectors: ErrorRate · Latency · Saturation   │
                 │                     (+ plugins) ─────────────► Signal (stateful)  │
                 │                                                 │                 │
                 │       Correlator ◄──────────────────────────────┘                 │
                 │       incidents · topology checks · cascades · noise inhibition   │
                 │       RootCauseAnalyzer · RuleEngine (alert_rules) · AlertBuilder │
                 └──────────────────────────────┬───────────────────────────────────┘
                                                │ AlertEvent: NEW / UPDATED / RESOLVED /
                                                ▼            REOPENED / MERGED
                        console dashboard · live events · JSON report · JSONL · HTTP
```

The domain model ([`models.py`](../src/log_analyzer/models.py)) has four stages:

| Type | Meaning | Volume (10k sample) |
|---|---|---|
| `LogEvent` | A normalised record, independent of format | 9,998 |
| `Signal` | One interpretation of something noteworthy: a line that matched a rule, or a detector observation. Carries a **fingerprint** (dedup key), a **category**, **targets** (dependencies it implicates) and an optional **effective start time** | 765 |
| `Incident` | A bounded aggregate of related signals | 416 opened, most never alert |
| `Alert` | The incident once it meets the alerting bar, in the spec's format | 5 |

Every stage is a small class with a single responsibility. The `Analyzer` is the only
orchestrator, and the CLI, the HTTP API and the tests all drive the same `Analyzer`.

## 4. Stage by stage

### 4.1 Parsing ([`ingest/parsers.py`](../src/log_analyzer/ingest/parsers.py))

- **Registry plus chain.** Built-in `otel`, `json`, `text` and `app` parsers register by name; `parsers.plugins: ["pkg.mod:Class"]` adds custom formats, which are tried first. A parser returns `None` when a line is not its format. A batch format may return several events for one line (`parse_batch`).
- **First-character dispatch.** `{` goes to OpenTelemetry then JSON, `[` to app, a digit to text. The candidate list is cached per first character.
- **Text format.** Optional milliseconds, optional `RequestID:`, level aliases (`WARNING`, `FATAL`, `ERR`…).
- **JSON format.** Key names are configurable (`timestamp`/`@timestamp`/`time`, ECS-style `service.name`, …). Nested objects are flattened, and leaf names are also exposed un-prefixed, so `details.active_connections` can be read as `active_connections`.
- **OpenTelemetry (OTLP/JSON).** Single log records and the OpenTelemetry Collector's export batches (`resourceLogs` → `scopeLogs` → `logRecords`, many records per line). The service is the `service.name` resource attribute; the level comes from `severityText`, else the `severityNumber` range; `body` and attribute `AnyValue`s are unwrapped; nanosecond timestamps fall back to `observedTimeUnixNano`. The trace id becomes the request id, so `estimated_failed_requests` counts distinct failed traces. A cheap substring check keeps ordinary JSON lines from being decoded twice. Counts such as "Logs Processed" are per record, not per physical line.
- **App (Monolog) format.** The trailing JSON context is parsed into fields, and Monolog's trailing `[]` is removed. The service comes from the context's `service` key, else the channel mapping, else a default.
- **Robustness.** Bad timestamps and levels make a parser decline the line. Unparsed lines are counted and sampled; stack-trace continuation lines are recognised and counted separately; over-long lines are truncated.

### 4.2 Filtering ([`processing/filters.py`](../src/log_analyzer/processing/filters.py))

Three filters run in order of cost, cheapest first:
1. the minimum level;
2. service globs (`dev-*`, `localhost`);
3. the spec's `ignore_patterns`, matched against the raw line so that `DEBUG.*development` works as written.

Each regex is compiled separately because patterns may carry their own inline flags, as
in `(?i)…`.

### 4.3 Classification ([`processing/classifier.py`](../src/log_analyzer/processing/classifier.py), [`config/defaults.yaml`](../src/log_analyzer/config/defaults.yaml))

**The rule library**
- About 25 rules ship as **data**: connection timeouts, pool exhaustion, refused and unavailable dependencies, retries, health checks, slow queries, memory and CPU, auth failures, and more.
- Each rule carries `severity`, a `category` (dependency / resource / availability / performance / application / security) and a runbook (`title`, `probable_cause`, `actions`).
- Rules are evaluated in order and the first match wins; specific rules come first.

**Capture conventions**
- Named groups have fixed meanings: `target_service` is the dependency the line blames, `timeout_ms` back-dates the failure, and `value` is compared against `threshold`.
- The spec's positional form (`Connection timeout to ([\w-]+)` with `group_by: [service, target_service]`) is also understood.

**Targets: who is to blame**
- Targets come from a capture, from a rule's static `target` (for example, pool exhaustion implicates `database`), or from **name or alias mentions** in dependency-type messages.
- Mentions are matched on hyphen- and case-normalised text, longest alias first, so "Payment provider unavailable" resolves to `payment-provider`, not `payment`.
- Every target must be a known service *and* plausible under the topology (§2.2).

**Unmatched lines**
- ERROR lines that match no rule still become *generic* signals, keyed by their message template (variable tokens collapsed to `<*>`). Unknown failure modes are grouped rather than lost.
- Unmatched WARN and INFO lines are only counted.

**Speed**
- Rules are bucketed by level, so INFO lines (about 90% of traffic) only meet the two rules that apply to them.
- A literal `prefilter` is checked before a regex runs.

### 4.4 Metric extraction ([`processing/metrics.py`](../src/log_analyzer/processing/metrics.py))

- Metric extractors are configured in YAML, like rules. Each returns either latency in milliseconds (from text such as `processed in 145ms`, or from fields such as `duration_ms` and `execution_time_ms`) or a utilization ratio (`Connection pool: 95/100`, or `active_connections` / `max_connections`).
- `Background job completed in …` is deliberately **not** treated as request latency: batch durations would pollute the request baseline.
- Implausible values are discarded: negative numbers, non-finite numbers, utilization above 200%.

### 4.5 Detectors ([`detectors/`](../src/log_analyzer/detectors))

All detectors keep per-key state in an LRU capped by `limits.max_tracked_keys`, and every
buffer has a fixed length.

#### Error-rate spike detection ([`detectors/error_rate.py`](../src/log_analyzer/detectors/error_rate.py))

Each service has a ring buffer of 5 s buckets holding total and error counts. Two rates
are compared:
- **current rate:** the last `error_rate_current` window (60 s);
- **baseline:** the previous `error_rate_baseline` window (300 s), never lower than the service's `expected_error_rate`.

```
spike  ⇔  errors_now ≥ min_occurrences  ∧  (rate_now ≥ 3 × baseline  ∨  rate_now ≥ absolute%)
```

Details:
- **The baseline floor matters.** With a clean history the learned baseline is 0%, and the first error would look like an infinite spike.
- **The absolute threshold only applies when it is above the service's expected rate.** A service declared to run at 20% errors is not on fire at 15%.
- **Buckets observed during a spike are excluded from future baselines.** A 17-minute outage is not silently re-learned as normal.
- **The cost of that choice:** chronically noisy services must declare a realistic `expected_error_rate`. That is an explicit, reviewable setting, which is better than an adaptive baseline that quietly stops alerting.
- **Signals are emitted on entry to a spike,** then as heartbeats every `alert_grouping / 2`, not once per error.

#### Latency degradation ([`detectors/latency.py`](../src/log_analyzer/detectors/latency.py))

There is one bounded series per (service, metric): the last 64 samples, at most 30 minutes
old. Over the newest `W = 20` samples, the series is **degrading** when all of these hold:
1. **Elevated:** the median of the newest half is at least 2× the baseline median.
2. **Sustained:** at least 70% of those samples are elevated. One slow request is not enough.
3. **Trending:** Kendall's τ ≥ 0.5, **and** the Mann-Kendall z-score ≥ 2.3 (p ≈ 0.01).
4. **Above the floor:** the newest median is at least 100 ms. A rise from 2 ms to 5 ms is not an incident.

Why test for a trend rather than a mean ratio:
- The sample data contains both a gradual slowdown and random slow requests (70–5000 ms) during the noise bands. Ratio tests flag both; a monotonic-trend test separates them.
- Testing *significance* rather than a fixed τ lets a short but perfectly monotonic series qualify. Spec Scenario 2 has five samples five minutes apart, z = 2.45. A short noisy run does not qualify; all the false positives seen in tuning had z between 1.6 and 2.2.

Other behaviour:
- **Severity** is MEDIUM below `performance_degradation_ms` and HIGH above it.
- **Projection:** a least-squares slope projects when the hard threshold will be crossed ("crosses 1000ms in ~2m 56s").
- **Baseline handling:** the baseline is frozen while degraded. Leaving the degraded state requires the ratio to fall below 75% of the trigger (hysteresis), so the alert doesn't flap.
- **Sparse vs dense:** signals record whether the baseline came from real history (dense) or from the window itself (sparse). Correlation uses this (§5.4).
- **Cheap gate:** a sample below 1.8× a cached baseline hint cannot *start* a degradation, so the O(W²) test only runs when it could matter.

#### Saturation ([`detectors/saturation.py`](../src/log_analyzer/detectors/saturation.py))

| Level | Condition | Severity |
|---|---|---|
| warning | utilization ≥ 80% and rising | MEDIUM, with a projected time to exhaustion |
| critical | utilization ≥ 95% | HIGH |
| exhausted | utilization ≥ 100% | HIGH |

On the 10k sample the warning fires at 14:24:31, projects exhaustion in about 60 s, and
the pool is exhausted at 14:25:12.

## 5. Correlation, root cause and noise

[`correlation/correlator.py`](../src/log_analyzer/correlation/correlator.py)

### 5.1 Linking rules

A signal joins every open incident it links to, and incidents it bridges are merged.

| # | Rule | Why |
|---|---|---|
| 1 | **Same fingerprint** | Deduplication: the same problem repeating |
| 2 | **Explicit evidence**: the signal names a dependency that is in the incident, or the incident already names this service as a failing dependency | Logs that blame a dependency are the strongest correlation evidence available |
| 3 | **Performance propagation**: a latency signal joins an incident where a configured neighbour is also degrading | Slowness propagates up call chains without any log naming it |
| 4 | **Same service**: weak signals (unclassified errors, rate spikes) join an incident already containing their service; stronger ones need a *confirmed* incident | Keeps one service's symptoms together without letting noise build chains |

What deliberately does **not** link two failures:
- time proximity alone;
- a static dependency edge alone;
- two services both blaming a dependency that never logs anything itself.

The last one is the path by which random "deadlock" and "too many connections" lines from
every service snowballed through `database` in testing.

### 5.2 Gating: when an incident becomes an alert

- **Multi-service incidents:** `min_occurrences` (3) related log signals within `alert_grouping` (60 s).
- **Single-service incidents:** the *same* fingerprint must repeat `min_occurrences` times within the window. A mix of different random errors is the error-rate detector's job, not a pattern alert.
- **Bypasses:** metric detectors, cascades, and per-rule `min_occurrences: 1` (for example, `OutOfMemoryError`).
- **Floor:** incidents whose severity stays below `min_alert_severity` (default MEDIUM) never page. Retries and invalid-request noise are evidence, not pages.

### 5.3 Cascades

The spec's `cascading_failure` rule (`multiple_services_failing_within_30_seconds`) is
evaluated **inside a correlated incident**:
- The first failing service is the origin.
- A newly failing service joins the cascade if its failure *began* within 30 s of the incident's latest failure. "Began" uses the timeout-corrected start: a line logged at T saying "timeout after 30000 ms" started failing at T − 30 s.
- At least `cascade_min_services` (3) members make it a cascade, and the incident is raised to the rule's severity.

On the 10k sample the pool incident's chain covers six services over 163 s, even though
each step arrived about 30.06 s after the previous one.

### 5.4 Noise: bucket, strength and inhibition

**The noise bucket**
- Error-rate spikes for services that no incident explains go into a single *unexplained* incident.
- It alerts once ("Elevated Error Rate Across N Services") with confidence 0.25 and "no common root cause".
- It is capped at MEDIUM when broad (more than 2 services) or heterogeneous (unique errors ÷ events ≥ 0.5).
- Customer `alert_rules` are not evaluated on it: "affected_services > 3" is meaningless for unrelated errors, and in testing it made the noise CRITICAL.
- It stays open for `noise_hold` (15 min) after its last spike, so intermittent spikes don't make it flap.

**Strength.** An incident is *strong* if any of these hold:
- a metric detector backs it (saturation, or a dense latency trend);
- its root is **corroborated**: the root reports the failure itself, another service names it as the failing dependency, and failures arrive as a burst (`min_occurrences` within the cascade window);
- it is CRITICAL with a root that logged its own failure.

Sparse latency trends count as strong only when no broad noise is active.

**Inhibition.** While a broad noise alert (3 or more services) is active:
- *weak* incidents are inhibited, and their logs are folded into the noise alert's evidence and statistics;
- weak alerts raised moments before the noise was recognised are merged into it, with a `MERGED` event.

Strong incidents always page: the real pool exhaustion starts while the first noise band's
bucket is still held open, and it still alerts.

### 5.5 Root cause analysis

[`correlation/rca.py`](../src/log_analyzer/correlation/rca.py)

**The graph**
- **Nodes:** the incident's services, plus dependencies named by failing services that never logged anything themselves (virtual nodes, such as a third-party API).
- **Edges:** dependent → dependency, from both observed evidence and configured topology.

**Scoring.** Each candidate is scored as:

```
score = (0.45·reach + 0.25·precedence + 0.30·intrinsic) / 1.0     (weights configurable)
score ×= 0.5   if the candidate itself depends on another failing node
```

| Term | Meaning |
|---|---|
| reach | Share of the other affected services that depend on the candidate, transitively |
| precedence | How early its failure started (timeout-corrected); earliest = 1 |
| intrinsic | 1.0 if it reports the problem *itself* ("pool exhausted", "health check failed", its own saturation); 0.7 for its own slowness; 0.4 for its own error-rate spike; 0.3 for application errors; 0.1 if it only blames someone else |

**Confidence**
- Confidence is the winning score.
- It is reduced by 20% when the runner-up is within 0.1 (ambiguous).
- It is capped at 0.98: this is inference from logs, not proof.
- Single-service incidents get 0.6 + 0.3 × intrinsic.

**Symptoms** are ordered by hop distance from the root, which produces the dashboard's
"database -> order-service, …, api-gateway".

### 5.6 Alert rules

[`correlation/rules.py`](../src/log_analyzer/correlation/rules.py)

- The spec's DSL (`all`/`any` over `pattern`, `service`, `affected_services`, `error_rate`, `duration`) is evaluated against each incident, extended with `root_cause`, `category`, `cascade`, `error_count`, `unique_errors` and `severity`. Groups can be nested.
- Inside a group that names a `service`, `error_rate` refers to *that* service's rate. That is the evident meaning of the spec's "API Gateway Cascade" rule.
- Matched rules raise severity (never lower it). The rule's name becomes the alert title only when that rule set the final severity.
- `auto_escalate` is surfaced on the alert as the hook for a paging integration.

## 6. Alert model

[`alerts/builder.py`](../src/log_analyzer/alerts/builder.py)

**Format**
- The JSON is the spec's format key for key, with extensions appended after the spec fields: status, category, root and symptom services, matched rules, detection time and severity history.
- IDs are `ALR-<date of first occurrence>-<sequence>`, deterministic per run.

**Lifecycle**

| Event | When |
|---|---|
| `NEW` | The incident first meets the alerting bar |
| `UPDATED` | Severity escalates, or the title or root changes. Alerts never de-escalate while open. |
| `RESOLVED` | No activity for `alert_grouping` |
| `REOPENED` | A detector condition recurs within `alert_cooldown`. It does not page again. |
| `MERGED` | Re-classified into noise |

**What an alert contains**
- **Evidence** is generated from the incident's aggregates, for example:
  - "database reported 'Connection pool exhausted' at 14:25:12";
  - "utilization rose from 50% to 100% between 14:23:00 and 14:25:12";
  - "4 services failed calling database from 14:25:12: inventory-service (18), …".
- **Suggested actions** come from the runbooks attached to rules and detectors in config. They are ordered with matched alert rules first, then the root's own signals, then cascade advice.
- **Sample logs** show the root service first, then one line per distinct (service, template).

**Metric definitions** (documented because the spec's example numbers are illustrative)

| Metric | Definition |
|---|---|
| `error_count` | ERROR+ lines attached to the incident |
| `unique_errors` | Distinct message templates |
| `estimated_failed_requests` | Distinct request IDs among error lines, plus error lines without an ID (capped set) |
| `total_logs_analyzed` | WARN+ lines attached to the incident, as signals or as context |
| `logs_grouped` | `total − unique_errors`: one representative kept per distinct error |
| `noise_reduction_percent` (per alert) | `logs_grouped / total` |
| Overall noise reduction | `1 − alerts / error lines`: the share of error lines that did not page anyone |

## 7. Time, streaming and memory

**Event time everywhere**
- Windows, rates, cascades, idle timeouts and "started 4m ago" all use log timestamps. Replaying a file is deterministic and matches live behaviour.
- The watermark is the latest timestamp seen. Slightly out-of-order events land in their correct bucket; events older than the retained window are ignored for rates.

**Streaming vs batch**
- **Batch (`--file`)** reads, analyzes and reports. Several files are merged by timestamp with a k-way heap merge, because cross-service correlation needs time order across sources.
- **Streaming (stdin)** reads on a background thread through a bounded queue, which provides back-pressure. The main loop wakes every `refresh_seconds`: it redraws the dashboard on a terminal and, when idle, advances event time by wall time so quiet incidents resolve.
- **API:** each `POST /analyze` uses a fresh `Analyzer` sharing the immutable config. The thread-per-request server needs no locks.

**Bounded memory**

| Structure | Bound |
|---|---|
| Error-rate buckets | (baseline + current) / bucket = 73 per service |
| Latency series | 64 samples, at most 30 min old, per (service, metric) |
| Saturation gauges | 32 readings |
| Per-key detector state, service counters, observed services | LRU, `max_tracked_keys` |
| Open incidents | `max_open_incidents`; the oldest are force-closed |
| Per incident | counters; the first signal per (service, kind); the latest detector reading; 24 sample lines; ≤ `max_request_ids` request IDs; ≤ `max_fingerprints` templates |
| Retained alerts | `max_retained_alerts` |
| Dashboard timeline | `max_timeline_buckets` |

Measured: 24 MB at 10k lines, 27 MB at 100k, 36 MB at 1M. The Python interpreter and
PyYAML account for about 20 MB of that.

## 8. Performance

Measured, not guessed: `cProfile`, plus stage ablation (switching one stage off at a time).

| Optimisation | Effect |
|---|---|
| Patterns compiled once at config load; one combined keyword regex per rule | Spec consideration 3 |
| Rules bucketed by level | INFO lines (90%) meet 2 of the 25 rules |
| Literal `prefilter` before regex | Skips most regex calls on INFO lines |
| First-character parser dispatch | No failed parse attempts on other formats |
| Greedy (not lazy) message capture in the line regexes | Removed backtracking on every character |
| Cheap pre-checks before RCA | RCA runs only for incidents that could alert; trend tests only for samples that could start a trend |
| Fast-path `datetime.fromisoformat` | Handles every timestamp form in the data in C |

Result: about 37k lines/s on one core. Processing has no hotspot left: the cost is spread
across parsing (about 25%), classification, detectors and bookkeeping. Further speed comes
from parallelism (§11), not micro-tuning.

## 9. Validation

**Spec scenarios** (exact lines from the problem statement), all automated tests:
1. One CRITICAL alert, root `database` (0.98). With 843 extra related errors it is still one alert, at 99.9% noise reduction.
2. A MEDIUM degradation alert at 09:20, before the 09:25 timeout.
3. Three dev lines ignored; one alert, for `production-api`.
4. 100k generated lines: under 5 s, under 100 MB, the correct incidents, and at least 95% noise reduction.

**Provided samples:** the 10k and 100k files each produce exactly five alerts, with the
correct roots. See [ANALYSIS.md](ANALYSIS.md).

**Robustness sweep** (`make robustness`; 12 generated datasets of 50k lines, different seeds):

| Measure | Result |
|---|---|
| Injected incidents detected with the correct root (pool exhaustion → database, payment outage → payment-provider, slowdown → database) | **36 / 36** |
| Noise reduction | 99.5–99.8% |
| Extra alerts | 7 in total (about 0.6 per dataset) |

The extra alerts appear in the first seconds of a noise band. They are random
combinations that are individually plausible, for example "notification-service memory at
95%" plus a gateway timing out on notification-service. They are reported honestly rather
than tuned away.

## 10. Trade-offs and alternatives

| Decision | Alternative | Why this way |
|---|---|---|
| Evidence plus topology-validated correlation | Time-window clustering; statistical co-occurrence | Time-based approaches produced fake CRITICAL cascades on the sample noise. Evidence is explainable at 3 AM ("X blamed Y"). Cost: needs either log evidence or configured dependencies. |
| Static topology from config | Topology learned from traces or a mesh | Config was the only source available here. In production, learn it from OpenTelemetry traces and keep config for overrides (§11). |
| Freeze the error-rate baseline during anomalies | Adaptive EWMA | An adaptive baseline quietly stops alerting during long outages. Freezing needs `expected_error_rate` for chronically noisy services, which is explicit and reviewable. |
| Kendall/Mann-Kendall trend test | EWMA ratio, z-score, CUSUM | Robust to outliers, no distribution assumptions, and works on 5 samples or 50. The sample data needs "monotonic" to separate the slowdown from random slow requests. |
| Rule library as YAML data | Rules in code; ML anomaly detection | Customers tune and override rules per environment, and every alert is explainable. ML belongs *behind* this layer (§12), not instead of it. |
| First matching rule wins | All matching rules | Deterministic and cheap; order is explicit in the file. |
| Standard-library HTTP server | FastAPI/uvicorn | The API is optional and simple; zero extra runtime dependencies. At scale, ingestion would be a queue consumer anyway. |
| Single process | Multiprocessing now | 37k lines/s meets the spec with a 2× margin. Correct parallelism needs partitioned state (§11), not a pool of workers sharing correlation state. |
| Python | Go/Rust | Readability and speed of iteration for a design-heavy problem. The hot path (parse and classify) is the part to port if needed. |

## 11. Scaling to millions of logs per minute

1M lines/min is about 17k lines/s, already within reach of one core of this engine. 10M+
lines/min across a fleet needs the pipeline split along its natural seams. The key
observation is that **signals are far rarer than log lines**: 7.6% in this deliberately
incident-heavy sample, and typically well under 1% of normal production traffic. So only
the first stages see full volume.

```
 apps ─► OTel Collector / Fluent Bit ─► Kafka "logs" (partitioned by service)
                                            │
                     ┌──────────────────────┴───────────────────────┐
                     ▼  N stateless+keyed workers (scale horizontally)
           parse → filter → classify → metrics → detectors (state keyed by service,
           RocksDB/Redis checkpointed; partitioning keeps a service's state local)
                     │ signals  (a small fraction of volume)
                     ▼
            Kafka "signals" ─► correlator (one per topology connected component,
                                or a single instance: signals are small)
                     │ alerts
                     ▼
            Alertmanager / PagerDuty (routing, silencing, escalation via auto_escalate)
 Raw logs ─► columnar store (e.g. ClickHouse) for search; alerts link to the query.
```

**Ingestion**
- Use the OpenTelemetry Collector or Fluent Bit at the edge.
- Do cheap filtering there: drop DEBUG and dev namespaces, and sample INFO, since INFO feeds only rates and latency, where sampling is statistically fine.
- Send to Kafka, partitioned by service, which keeps per-service ordering.

**Stateless stages**
- Parse, filter, classify and extract metrics as consumers in a group; scale by adding partitions and pods.
- The rule library is the same YAML, hot-reloaded.

**Stateful detectors**
- Keyed by service, so they are co-located with the partition.
- State is small and bounded (ring buffers, 64-sample series) and is checkpointed: Kafka Streams/Flink state stores, or periodic snapshots.

**Correlation**
- Needs a cross-service view, but only of signals.
- One instance handles tens of thousands of signals per second. Beyond that, shard by connected component of the service graph, so services that can be linked land on the same shard.

**Topology**
- Learn it continuously from distributed traces (the OTel service graph) instead of maintaining it by hand.
- That also gives request-level error rates, rather than per-line ones, and replaces alias guessing with real span attributes.

**Event time at scale**
- Use watermarks with allowed lateness per partition; this engine already uses watermarks.
- Close windows on the watermark, not wall time; handle late data explicitly.

**Operations**
- Expose the analyzer's own metrics (lines/s, lag, unparsed rate, open incidents, alert rate) to Prometheus, and alert on the alerter.
- Config changes go through CI (`validate-config`) and canary.
- If profiling shows the CPU hot path dominates, port parse and classify to Go or Rust, or run under PyPy. The rest (correlation, RCA, alerting) is signal-volume and stays in Python.

## 12. Future work

- **Learned baselines** for latency and error rate (seasonality, time of day), as an input to the detectors, keeping the explainable rule layer on top.
- **Log template mining** (for example Drain) to cluster unknown errors automatically, instead of the digit-collapsing heuristic.
- **Feedback loop:** on-call marks an alert as noise or useful, and per-pattern thresholds adapt.
- **Change correlation:** ingest deploy and config-change events, and rank "recent deployment of X" as a root-cause candidate.
- **Multi-line event assembly** (stack traces attached to their error) with a short buffer per source.
- **Persistence** of open incidents across restarts in streaming mode.
