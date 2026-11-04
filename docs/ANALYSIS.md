# Analysis of the provided sample logs

This report covers the two provided datasets: what is in them, which alerts the analyzer
raises, and why. It also covers what the analyzer deliberately does **not** alert on. The
alerts are reproducible with:

```bash
make report        # writes reports/sample_{10k,100k}{.json,_dashboard.txt}
```

Configuration: [`configs/config.yaml`](../configs/config.yaml) (sample topology, dev-service filters).

## 1. Summary

| | 10k sample (`test_logs.txt`) | 100k sample (`large_test_logs.txt`) |
|---|---:|---:|
| Lines | 9,998 | 99,998 |
| Time span | 14:03:49 – 15:00:34 (57 min) | 14:08:01 – 20:30:24 (6 h 22 min) |
| Formats (text / JSON / app) | 4,436 / 2,901 / 2,661 | 42,420 / 30,241 / 27,337 |
| Unparseable lines | 0 | 0 |
| Ignored (DEBUG / dev services) | 273 | 2,793 |
| ERROR lines | 447 | 3,251 |
| WARN lines | 413 | 3,186 |
| **Alerts** | **5** | **5** |
| **Noise reduction** (1 − alerts ÷ error lines) | **98.9%** | **99.8%** |
| Processing time / peak memory | 0.26 s / 24 MB | 2.7 s / 27 MB |

Both files contain the same five incidents, and the analyzer raises the same five alerts
for each:

| # | Alert | Severity | Root cause | Confidence |
|---|---|---|---|---|
| 1 | Performance Degradation: Rising Database Query Time Affecting 3 Dependent Services | MEDIUM | database | 0.91 |
| 2 | Elevated Error Rate Across 10 Services (noise band 1) | MEDIUM | none identified | 0.25 |
| 3 | **Database Connection Crisis** | **CRITICAL** | **database** | **0.98** |
| 4 | **Payment Provider Health Checks Failing - Cascading Failure Across 5 Services** | **CRITICAL** | **payment-provider** | **0.98** |
| 5 | Elevated Error Rate Across 10 Services (noise band 2) | MEDIUM | none identified | 0.25 |

## 2. What is in the data

Profiling the 10k file segment by segment (line ranges are from the 10k file; the 100k file
has the same shape, scaled up):

| Lines | Time | Content |
|---|---|---|
| 1–2000 | 14:03:49–14:05:39 | Normal traffic, all INFO, three formats interleaved |
| 2001–2200 | 14:05:39–14:06:37 | DEBUG noise from `dev-server`, `localhost`, `test-runner`, `debug-console` |
| 2201–2315 | 14:06:37–14:07:33 | **Gradual degradation**: DB query time 58 → 308 ms, request latency 115 → 441 ms on 3 services |
| 2316–4315 | 14:07:33–14:09:24 | Normal traffic |
| 4316–4615 | 14:09:24–14:22:55 | **Random errors/warnings band**: 300 lines, ~20 templates, random targets, many garbled values |
| 4616–4725 | 14:23:00–14:42:28 | **DB pool exhaustion**: pool 50% → 88% (INFO), 90–98% (WARN), exhausted (ERROR); then 17 min of DB clients failing and gateway timeouts |
| 4726–6226 | 14:43:28–14:44:50 | Normal traffic |
| 6227–6317 | 14:44:50–14:45:29 | **Payment cascade**: provider refuses connections, then payment-service fails and retries, then orders, gateway and web app fail |
| 6318–9631 | 14:45:29–14:48:32 | Normal traffic |
| 9632–9925 | 14:48:32–15:00:34 | **Random errors/warnings band** |
| 9926–9998 | 15:00:39–15:00:58 | DEBUG noise |

## 3. The alerts, one by one

The times and figures below are from the 10k file.

### Alert 1: MEDIUM, Performance Degradation: Rising Database Query Time Affecting 3 Dependent Services

> Database query time rose to 172ms (2.39x the 72ms baseline) and is still trending up;
> dependents also slowing: order-service, search-service, api-gateway. At this rate it
> crosses 1000ms in about 2m 56s.

**Why it fired.** No single line in this segment crosses the 1000 ms performance
threshold, so a threshold rule would stay silent. The latency detector saw four series
rising *monotonically*: the database's query time (Kendall τ 0.63) and the request latency
of order-service, api-gateway and search-service (τ 0.67–0.77). Each series' newest
samples were 2.2–2.7× its baseline.

**Why one alert.** Slowness propagates up call chains without any log naming it, so
latency signals link along configured dependencies:
- api-gateway → order-service and search-service;
- order-service and search-service → database.

**Root cause.** The database is the deepest node, everything else depends on it, and its
degradation started first (14:07:09, against 14:07:24–29 for the dependents).

**Why MEDIUM.** Still below the hard threshold. This is the "alert before complete
failure occurs" case, and the alert projects when the threshold will be crossed.

**What the engineer does.** Look at the slow-query log and recent deploys on the
database, and scale out or shed load before latency reaches timeouts.

### Alert 3: CRITICAL, Database Connection Crisis

> database: Database connection pool exhausted, causing cascading failures in 5 dependent
> services: order-service, inventory-service, payment-service, user-service, api-gateway.

**Evidence produced**
- database reported 'Connection pool exhausted' at 14:25:12.
- database connection pool utilization rose from 50% to 100% between 14:23:00 and 14:25:12.
- Early warning at 14:24:31: 80% and rising, projected exhaustion in about 1 min.
- 4 services failed calling database from 14:25:12: inventory-service (18), user-service (17), order-service (9), payment-service (6).
- api-gateway was failing on inventory-service, order-service, payment-service and user-service (34 errors).
- 6 services began failing in a chain, each within 30 s of the previous failure; first to last took 163 s.

**Timeline of the alert itself.** It opened **MEDIUM at 14:24:31**, the saturation
early warning, 41 s before the pool actually ran out. It escalated to **HIGH at 14:25:08**
at 96% and to **CRITICAL at 14:25:42** once the cascade formed and the spec's "Database
Connection Crisis" rule matched ("connection pool exhausted" with more than 3 affected
services, `auto_escalate`). It resolved after 17 min 57 s of activity.

**Why one alert for 90 lines over 18 minutes**
- Every DB client error names the database ("Failed to acquire database connection").
- Every gateway error names its upstream ("Connection timeout to order-service").
- All of those claims agree with the configured topology.

**One subtle point.** The gateway's timeouts are logged about 30.06 s after the failure
that caused them, because the client timeout is 30000 ms. A strict 30 s cascade window
would split the incident by 60 ms. The analyzer back-dates each timeout by its duration,
so the chain stays intact.

**Root cause.** `database`, confidence 0.98: it reports the problem itself, all other
affected services depend on it, and it failed first.

**Noise reduction.** 85 error lines and 90 WARN+ lines in total, in 7 distinct templates,
became one page.

### Alert 4: CRITICAL, Payment Provider Health Checks Failing - Cascading Failure Across 5 Services

> payment-provider: Health checks failing - service down or unreachable, causing cascading
> failures in 4 dependent services: payment-service, order-service, api-gateway, web-app.

**Evidence produced**
- payment-provider reported "Service health check failed: Connection refused" at 14:44:50.
- payment-service failed calling it 40 times from 14:44:52 ("Payment provider unavailable: connection refused", plus 3 retries per request).
- order-service: "Cannot process order: payment service unavailable" (15).
- web-app (the Monolog "production" channel): "Customer order failed {… Payment processing unavailable}" (20); the JSON context is searched too.
- api-gateway: "Order processing failed: downstream service error".

**Root cause.** `payment-provider`, a third party, with confidence 0.98: it reported its
own failure and is the dependency every other failing service leads to.

**Cascade.** Five services began failing in a chain over 31 s.

**Actions.** Fix the provider side, or fail over; open circuit breakers on dependents to
stop retry amplification (each failed payment produced 3 retries).

### Alerts 2 and 5: MEDIUM, Elevated Error Rate Across 10 Services (two noise bands)

> 10 services show elevated error rates with 62 distinct error signatures and no shared
> failing dependency; likely background noise or a broad change (deploy/config).

These two bands are the generator's "random errors and warnings":
- About 20 templates with random parameters, spread evenly across all ten services.
- Many values cannot be real: `CPU usage at 3748%`, `Request processed in ord_78642ms`, `Connection timeout to file_007f1c1f.txt after user-servicems`.

**How they are handled**
- Every service's error rate genuinely jumps (from 0 to 50–100% of its lines), so one alert per band is correct. It is MEDIUM, with "no common root cause" and confidence 0.25, rather than 117 or 137 pages.
- The messages *name real services* at random, for example order-service saying an "api-gateway connection attempt timed out". The analyzer only accepts such claims when they match the topology: order-service does not call the gateway, so that claim is not treated as evidence.
- Small, individually plausible chains that still form by chance are folded into the band's alert as *weak* incidents (inhibition). Their logs appear in its evidence and statistics.
- The spec's customer rules ("Database Connection Crisis", "API Gateway Cascade") are deliberately **not** evaluated on this unrelated-errors bucket. Random "Connection pool exhausted" lines from four or more unrelated services would otherwise turn background noise CRITICAL.

## 4. What was deliberately not alerted on

| Input | Lines (10k) | Why it did not page |
|---|---:|---|
| DEBUG lines from dev and test services | 273 | `filters.min_level: INFO` and `ignore_services: [dev-*, localhost, test-*, debug-*]` |
| Garbled numbers (`ord_78642ms`, `usr_3521ms`, `file_….txtms`) | 1,321 | Metric and threshold rules require digits, so garbled values never become latency samples or slow-query alerts |
| Impossible percentages (`CPU usage at 3748%`, `memory usage 3228%`) | 26 | `value_range: [0, 100]` on resource rules |
| Dependency claims to non-services (`Connection timeout to 603`, `to file_007f1c1f.txt`) | dozens | Targets must resolve to a known service |
| Dependency claims that contradict the topology | dozens | `ServiceDirectory.plausible`: order-service cannot fail calling the gateway that calls it |
| Retries, invalid requests, rate limiting, missing files | 113 | Severity LOW, below `min_alert_severity: MEDIUM`; kept as evidence |
| Random slow requests (70–5000 ms) in the noise bands | ~30 | Not a monotonic trend (Mann-Kendall test); sparse trends during broad noise count as weak |
| Error-rate spikes inside real incidents | many | They join the incident they belong to as evidence ("order-service error rate 100%") |

## 5. The 100k sample

The large file has the same structure, stretched over 6 h 22 min:
- the degradation at 14:36;
- a 2-hour noise band from 14:55 to 17:04;
- the pool exhaustion from 17:05 to 17:25;
- the payment cascade at 17:39;
- a second 2-hour noise band from 18:13 to 20:30.

The analyzer produces the same five alerts with the same root causes and confidences. The
pool exhaustion early warning fires at 17:05:33, and the pool runs out at 17:06.

The two 2-hour noise bands contain 2,768 and 2,955 WARN+ lines respectively. Each stays one
MEDIUM alert for its whole duration: the noise alert is held open for 15 minutes between
sparse spikes, so it doesn't flap.

| Metric | Value |
|---|---|
| Lines processed | 99,998 |
| Processing time | 2.68 s (37k lines/s) |
| Peak memory | 27 MB |
| Error lines → alerts | 3,251 → 5 (99.8% noise reduction) |

## 6. Observations for the customer

1. **The pool exhaustion was predictable 40 s ahead.** The utilization trend gave a usable
   early warning, so a page at 80% and rising would have allowed a pool-size bump before
   any customer-facing errors.
2. **Retry amplification.** During the payment outage, each failed payment was retried 3
   times within about 250 ms. Backoff with jitter and a circuit breaker on
   payment-provider would cut the error volume by about 4×.
3. **Logging hygiene.** Several services log garbage parameters (`ord_78642ms`, `CPU usage
   at 3748%`, `Connection timeout to file_….txt`). These are worth fixing at the source:
   they make naive alerting impossible and waste storage.
4. **Topology.** Correlation quality depends on knowing who calls whom. Feeding the
   dependency graph from tracing would remove the need for the hand-written `services`
   section.
