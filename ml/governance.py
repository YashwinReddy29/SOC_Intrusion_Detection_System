"""Model-governance policy and reproducibility evidence."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from ml.feature_extractor import FEATURE_COLUMNS


DEFAULT_GATES = {
    "precision": 0.89,
    "recall": 0.87,
    "f1": 0.88,
}


def sha256_file(path: str | Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def validate_feature_contract(feature_columns: list[str]) -> None:
    if list(feature_columns) != FEATURE_COLUMNS:
        raise ValueError(
            "model feature contract mismatch: "
            f"expected {FEATURE_COLUMNS}, got {list(feature_columns)}"
        )


def evaluate_quality_gates(
    metrics: dict,
    *,
    minimums: dict[str, float] | None = None,
) -> tuple[bool, list[str]]:
    gates = dict(DEFAULT_GATES)
    if minimums:
        gates.update(minimums)

    reasons: list[str] = []
    for metric, minimum in gates.items():
        value = metrics.get(metric)
        if value is None:
            reasons.append(f"missing metric: {metric}")
            continue
        if float(value) < float(minimum):
            reasons.append(
                f"{metric}={float(value):.4f} is below required {float(minimum):.4f}"
            )

    if metrics.get("precision_target_met_on_validation") is False:
        reasons.append("validation precision target was not met")

    return not reasons, reasons


def evaluate_candidate_against_champion(
    candidate: dict,
    champion: dict | None,
    *,
    maximum_regression: dict[str, float] | None = None,
) -> tuple[bool, list[str]]:
    passed, reasons = evaluate_quality_gates(candidate)
    if champion is None:
        return passed, reasons

    regression = {
        "precision": 0.02,
        "recall": 0.03,
        "f1": 0.02,
    }
    if maximum_regression:
        regression.update(maximum_regression)

    for metric, allowed_drop in regression.items():
        if metric not in candidate or metric not in champion:
            reasons.append(f"cannot compare champion metric: {metric}")
            continue
        drop = float(champion[metric]) - float(candidate[metric])
        if drop > float(allowed_drop):
            reasons.append(
                f"{metric} regression {drop:.4f} exceeds allowed {allowed_drop:.4f}"
            )

    return not reasons, reasons


def build_reproducibility_manifest(
    *,
    model_path: str | Path,
    metrics_path: str | Path,
    dataset_path: str | Path,
    feature_columns: list[str],
    metrics: dict,
) -> dict:
    validate_feature_contract(feature_columns)
    manifest = {
        "model_sha256": sha256_file(model_path),
        "metrics_sha256": sha256_file(metrics_path),
        "dataset_sha256": sha256_file(dataset_path),
        "feature_columns": list(feature_columns),
        "feature_count": len(feature_columns),
        "model_version": metrics.get("model_version"),
        "split_strategy": metrics.get("split_strategy"),
        "dataset_size": metrics.get("dataset_size"),
        "train_size": metrics.get("train_size"),
        "validation_size": metrics.get("validation_size"),
        "test_size": metrics.get("test_size"),
        "quality": {
            key: metrics.get(key)
            for key in ("precision", "recall", "f1", "accuracy")
        },
    }
    passed, reasons = evaluate_quality_gates(metrics)
    manifest["promotion_gate"] = {"passed": passed, "reasons": reasons}
    return manifest


def save_manifest(manifest: dict, path: str | Path) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(manifest, indent=2, sort_keys=True), encoding="utf-8")
