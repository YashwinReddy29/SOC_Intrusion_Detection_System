# Phase 2 validation contract

Base: production-v3-platform

This phase owns incident lifecycle, analyst workflow, RBAC, deduplication, notes, assignment, and audit history.

Validation requirements:
- Existing Phase 1 tests remain green.
- State transition matrix is tested.
- RBAC matrix is tested.
- Assignment and notes persist.
- Audit history is append-only.
- Duplicate alerts do not duplicate incidents.
- Full CI and integration smoke tests pass.
