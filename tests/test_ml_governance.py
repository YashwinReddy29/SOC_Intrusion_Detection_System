from __future__ import annotations

import json

import pytest

from ml.feature_extractor import FEATURE_COLUMNS
from ml.governance import (
    build_reproducibility_manifest,
    evaluate_candidate_against_champion,
    evaluate_quality_gates,
    validate_feature_contract,
)


def good_metrics():
    return {
        "precision": 0.91,
        "recall": 0.90,
        "f1": 0.905,
        "accuracy": 0.94,
        "precision_target_met_on_validation": True,
        "model_version": "2.1.0",
        "split_strategy": "chronological_70_15_15",
        "dataset_size": 10000,
        "train_size": 7000,
        "validation_size": 1500,
        "test_size": 1500,
    }


def test_quality_gate_accepts_target_metrics():
    passed, reasons = evaluate_quality_gates(good_metrics())
    assert passed
    assert reasons == []


def test_quality_gate_rejects_regression():
    metrics = good_metrics()
    metrics["f1"] = 0.70
    passed, reasons = evaluate_quality_gates(metrics)
    assert not passed
    assert any("f1=" in reason for reason in reasons)


def test_candidate_cannot_regress_too_far_from_champion():
    champion = good_metrics()
    candidate = good_metrics()
    candidate["recall"] = 0.875
    passed, reasons = evaluate_candidate_against_champion(candidate, champion)
    assert not passed
    assert any("recall regression" in reason for reason in reasons)


def test_feature_contract_is_exact():
    validate_feature_contract(FEATURE_COLUMNS)
    with pytest.raises(ValueError):
        validate_feature_contract(FEATURE_COLUMNS[:-1])


def test_manifest_hashes_artifacts(tmp_path):
    model = tmp_path / "model.joblib"
    report = tmp_path / "metrics.json"
    dataset = tmp_path / "events.csv"
    model.write_bytes(b"model")
    report.write_text(json.dumps(good_metrics()), encoding="utf-8")
    dataset.write_text("a,b\n1,2\n", encoding="utf-8")

    manifest = build_reproducibility_manifest(
        model_path=model,
        metrics_path=report,
        dataset_path=dataset,
        feature_columns=FEATURE_COLUMNS,
        metrics=good_metrics(),
    )
    assert manifest["feature_columns"] == FEATURE_COLUMNS
    assert len(manifest["model_sha256"]) == 64
    assert manifest["promotion_gate"]["passed"] is True
