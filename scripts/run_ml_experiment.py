"""Run the leakage-safe v2 SOC ML experiment end-to-end.

The dataset is generated across 30 days with normal and attack traffic interleaved.
Splits are chronological, while rolling features are computed once over the full
ordered stream so online feature state is causal (current event + prior events only).
"""

from pathlib import Path
import json
import os

import pandas as pd
from sklearn.metrics import f1_score, precision_score, recall_score

from ml.eval_metrics import benchmark_scorer, evaluate, save_metrics, tune_threshold
from ml.feature_extractor import RollingFeatureExtractor
from ml.ml_service import MLService
from ml.synthetic_data_generator import GeneratorConfig, generate_dataset, save_dataset


ROOT = Path(__file__).resolve().parents[1]
DATA_PATH = ROOT / "ml" / "data" / "soc_events_v2.csv"
MODEL_PATH = ROOT / "ml" / "models" / "isolation_forest.joblib"
REPORT_PATH = ROOT / "ml" / "reports" / "ml_metrics_v2.json"
MANIFEST_PATH = ROOT / "ml" / "reports" / "model_manifest_v2.json"


def _distribution(frame: pd.DataFrame) -> dict:
    return frame["label"].value_counts().sort_index().to_dict()


def _attack_breakdown(frame: pd.DataFrame, predictions) -> dict:
    """Calculate recall/F1 for each attack family in the test period."""
    labels = frame["label"].astype(int).reset_index(drop=True)
    attack_types = frame["attack_type"].reset_index(drop=True)
    predictions = pd.Series(predictions).reset_index(drop=True)

    result = {}
    for attack_type in sorted(attack_types[attack_types != "normal"].unique()):
        mask = attack_types == attack_type
        y_true = labels[mask]
        y_pred = predictions[mask]
        result[attack_type] = {
            "count": int(mask.sum()),
            "precision": float(precision_score(y_true, y_pred, zero_division=0)),
            "recall": float(recall_score(y_true, y_pred, zero_division=0)),
            "f1": float(f1_score(y_true, y_pred, zero_division=0)),
        }
    return result


def main():
    print("[1/7] Generating 10,000 realistic temporal SOC events...")
    DATA_PATH.parent.mkdir(parents=True, exist_ok=True)
    MODEL_PATH.parent.mkdir(parents=True, exist_ok=True)
    REPORT_PATH.parent.mkdir(parents=True, exist_ok=True)

    df = generate_dataset(
        GeneratorConfig(total_events=10_000, attack_fraction=0.20, seed=42)
    )
    df["timestamp"] = pd.to_datetime(df["timestamp"], utc=True)
    df = df.sort_values("timestamp").reset_index(drop=True)
    save_dataset(df, str(DATA_PATH))
    print(df["label"].value_counts().sort_index().to_dict())

    print("[2/7] Creating chronological train/validation/test periods...")
    n = len(df)
    train_end = int(n * 0.70)
    val_end = int(n * 0.85)

    train_df = df.iloc[:train_end].copy()
    val_df = df.iloc[train_end:val_end].copy()
    test_df = df.iloc[val_end:].copy()

    print(f"Train={len(train_df)}, Validation={len(val_df)}, Test={len(test_df)}")
    print(f"Train labels: {_distribution(train_df)}")
    print(f"Validation labels: {_distribution(val_df)}")
    print(f"Test labels: {_distribution(test_df)}")
    print(
        "Validation attack families:",
        val_df.loc[val_df["label"] == 1, "attack_type"].value_counts().sort_index().to_dict(),
    )
    print(
        "Test attack families:",
        test_df.loc[test_df["label"] == 1, "attack_type"].value_counts().sort_index().to_dict(),
    )

    for name, frame in [("Train", train_df), ("Validation", val_df), ("Test", test_df)]:
        if not ((frame["label"] == 0).any() and (frame["label"] == 1).any()):
            raise RuntimeError(
                f"{name} period must contain both normal and attack events"
            )

    print("[3/7] Building rolling behavioral features in time order...")
    extractor = RollingFeatureExtractor(window_seconds=300)
    train_normal_timestamps = train_df.loc[train_df["label"] == 0, "timestamp"]
    extractor.fit_time_statistics(train_normal_timestamps)
    features = extractor.transform(df, reset=True)
    labels = df["label"].astype(int).reset_index(drop=True)

    X_train = features.iloc[:train_end].reset_index(drop=True)
    y_train = labels.iloc[:train_end].reset_index(drop=True)
    X_val = features.iloc[train_end:val_end].reset_index(drop=True)
    y_val = labels.iloc[train_end:val_end].reset_index(drop=True)
    X_test = features.iloc[val_end:].reset_index(drop=True)
    y_test = labels.iloc[val_end:].reset_index(drop=True)

    print("[4/7] Training Isolation Forest on NORMAL training traffic only...")
    service = MLService(str(MODEL_PATH))
    train_info = service.train(X_train, y_train)
    service.set_feature_stats(extractor.time_mean, extractor.time_std)

    val_scores = service.anomaly_scores(X_val)
    selected, target_met = tune_threshold(y_val, val_scores, min_precision=0.89)
    service.set_threshold(selected["threshold"])

    print("Validation operating point:")
    print(json.dumps(selected, indent=2))
    print(f"89% precision target met: {target_met}")

    print("[5/7] Evaluating untouched chronological test period...")
    test_scores = service.anomaly_scores(X_test)
    test_predictions = (test_scores >= service.threshold).astype(int)
    latencies = benchmark_scorer(service, X_test)

    metrics = evaluate(
        y_test,
        test_predictions,
        latencies_ms=latencies,
        threshold=service.threshold,
    )
    metrics.update(
        {
            "dataset_size": int(len(df)),
            "attack_count": int(labels.sum()),
            "normal_count": int((labels == 0).sum()),
            "training_samples": train_info["training_samples"],
            "train_size": int(len(train_df)),
            "validation_size": int(len(val_df)),
            "test_size": int(len(test_df)),
            "validation_attack_count": int(y_val.sum()),
            "validation_normal_count": int((y_val == 0).sum()),
            "test_attack_count": int(y_test.sum()),
            "test_normal_count": int((y_test == 0).sum()),
            "validation_precision": selected["precision"],
            "validation_recall": selected["recall"],
            "validation_f1": selected["f1"],
            "precision_target_met_on_validation": target_met,
            "split_strategy": "chronological_70_15_15",
            "attack_family_metrics_test": _attack_breakdown(test_df, test_predictions),
            "model_version": service.VERSION,
        }
    )

    service.save()
    save_metrics(metrics, str(REPORT_PATH))

    from ml.governance import build_reproducibility_manifest, save_manifest

    manifest = build_reproducibility_manifest(
        model_path=MODEL_PATH,
        metrics_path=REPORT_PATH,
        dataset_path=DATA_PATH,
        feature_columns=service.feature_columns,
        metrics=metrics,
    )
    save_manifest(manifest, MANIFEST_PATH)

    if os.getenv("MLFLOW_TRACKING_URI"):
        from ml.mlflow_registry import log_training_run

        mlflow_result = log_training_run(
            service=service,
            metrics=metrics,
            feature_sample=X_train,
            artifact_path=MODEL_PATH,
            report_path=REPORT_PATH,
            manifest_path=MANIFEST_PATH,
        )
        print("MLflow:")
        print(json.dumps(mlflow_result, indent=2))

    print("[6/7] Per-attack TEST metrics")
    print(json.dumps(metrics["attack_family_metrics_test"], indent=2))

    print("[7/7] Final TEST metrics")
    print(json.dumps(metrics, indent=2))
    print(f"\nSaved dataset: {DATA_PATH}")
    print(f"Saved model:   {MODEL_PATH}")
    print(f"Saved report:  {REPORT_PATH}")
    print(f"Saved manifest:{MANIFEST_PATH}")


if __name__ == "__main__":
    main()
