# Phase 3 validation contract

Base: production-v3-phase2-incidents

This phase owns database migrations, Kafka replay/recovery, schema evolution, threat-intelligence enrichment, and data-integrity checks.

Validation requirements:
- Fresh and upgrade database paths.
- No event/incident loss across migration.
- DLQ replay idempotency.
- Threat-intel timeout/error/cache behavior.
- Backward-compatible event schema validation.
- Full previous-phase regression suite.
