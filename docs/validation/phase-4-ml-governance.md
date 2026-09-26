# Phase 4 validation contract

Base: production-v3-phase3-data-recovery

This phase owns model lifecycle governance and validation.

Validation requirements:
- 7-feature contract is exact.
- Chronological split/leakage safeguards remain intact.
- MLflow metadata/artifacts are reproducible.
- Promotion gates and rollback are tested.
- Evidently drift output is machine-readable.
- SHAP output matches the model feature set.
- Previous-phase regression suite remains green.
