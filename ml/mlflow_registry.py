"""Optional MLflow tracking and model-registry integration."""

from __future__ import annotations

import os
from pathlib import Path


DEFAULT_MODEL_NAME = "soc-isolation-forest"
DEFAULT_EXPERIMENT = "soc-intrusion-detection"


def log_training_run(
    service,
    metrics: dict,
    feature_sample,
    artifact_path: str | Path,
    report_path: str | Path,
    manifest_path: str | Path,
) -> dict:
    tracking_uri = os.getenv("MLFLOW_TRACKING_URI")
    if not tracking_uri:
        return {"enabled": False}

    import mlflow
    import mlflow.sklearn

    mlflow.set_tracking_uri(tracking_uri)
    mlflow.set_experiment(
        os.getenv("MLFLOW_EXPERIMENT_NAME", DEFAULT_EXPERIMENT)
    )
    model_name = os.getenv("MLFLOW_MODEL_NAME", DEFAULT_MODEL_NAME)

    with mlflow.start_run() as run:
        mlflow.log_params(
            {
                "algorithm": "IsolationForest",
                "n_estimators": 400,
                "random_state": 42,
                "feature_count": len(service.feature_columns),
                "split_strategy": metrics.get("split_strategy"),
                "threshold": service.threshold,
                "model_version": service.VERSION,
            }
        )

        for key in (
            "precision",
            "recall",
            "f1",
            "accuracy",
            "validation_precision",
            "validation_recall",
            "validation_f1",
            "latency_ms_mean",
            "latency_ms_p95",
            "latency_ms_p99",
        ):
            value = metrics.get(key)
            if value is not None:
                mlflow.log_metric(key, float(value))

        mlflow.log_artifact(str(artifact_path), artifact_path="model_bundle")
        mlflow.log_artifact(str(report_path), artifact_path="reports")
        mlflow.log_artifact(str(manifest_path), artifact_path="governance")

        info = mlflow.sklearn.log_model(
            sk_model=service.model,
            name="sklearn_model",
            registered_model_name=model_name,
            input_example=feature_sample.head(5),
        )

        return {
            "enabled": True,
            "run_id": run.info.run_id,
            "model_name": model_name,
            "model_uri": info.model_uri,
        }
