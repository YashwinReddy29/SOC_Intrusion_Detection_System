# SOC Platform SLOs and operational signals

## Service objectives

The production-v3 operating targets are intentionally defined separately from benchmark claims. A target is not evidence that the implementation currently achieves it.

| Signal | Objective | Alert threshold |
| --- | --- | --- |
| API server-error ratio | < 1% over rolling 5 minutes | > 1% for 10 minutes |
| API request p95 | < 250 ms | > 250 ms for 10 minutes |
| Detector processing p95 | < 100 ms | > 100 ms for 10 minutes |
| Required dependency readiness | 100% while serving traffic | dependency gauge = 0 for 2 minutes |
| Kafka detector lag | < 100 records per partition | > 100 for 5 minutes |

These objectives are conservative operational guardrails. Final release benchmarks are recorded separately in Phase 6 and must never be inferred from these thresholds.

## Bounded metric labels

Application metrics use bounded labels only: HTTP method, Flask endpoint name, status code, detector severity/detected state, fixed processing state, fixed dependency names, and Kafka topic/partition. Raw source IPs, event IDs, user names, API keys, request bodies, and incident summaries must not be Prometheus labels.

## Failure interpretation

- /health is process liveness only and should remain healthy when an external dependency is unavailable.
- /ready verifies the model, database, Redis, and Kafka when configured. A failed required dependency removes the API from service.
- Kafka worker availability is independently scraped from port 9101.
- Threat-intelligence enrichment is fail-open and is not a readiness dependency; detection must continue when enrichment times out.

## Operator response

1. Identify the firing alert and dependency/endpoint labels.
2. Check Grafana for request rate, p95 latency, detection latency, dependency gauges, and Kafka lag.
3. Follow the trace using the request correlation ID when the failure is on an HTTP path.
4. For Kafka lag, verify broker health and worker logs before scaling workers.
5. For PostgreSQL/Redis/Kafka outages, restore the dependency before restarting healthy application containers.
6. Use DLQ replay only after the underlying processing failure is resolved.
