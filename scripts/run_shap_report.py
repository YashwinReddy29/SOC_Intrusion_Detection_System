"""Generate reproducible SHAP feature-attribution evidence for the detector."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

import numpy as np
import pandas as pd
import shap

from ml.feature_extractor import FEATURE_COLUMNS, RollingFeatureExtractor
from ml.ml_service import MLService
from ml.synthetic_data_generator import GeneratorConfig, generate_dataset


ROOT = Path(__file__).resolve().parents[1]


def load_frame(path: Path) -> pd.DataFrame:
    if path.exists():
        frame = pd.read_csv(path)
    else:
        frame = generate_dataset(
            GeneratorConfig(total_events=10_000, attack_fraction=0.20, seed=42)
        )
    frame["timestamp"] = pd.to_datetime(frame["timestamp"], utc=True)
    return frame.sort_values("timestamp").reset_index(drop=True)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--data",
        type=Path,
        default=ROOT / "ml" / "data" / "soc_events_v2.csv",
    )
    parser.add_argument(
        "--model",
        type=Path,
        default=ROOT / "ml" / "models" / "isolation_forest.joblib",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=ROOT / "ml" / "reports" / "shap_feature_importance.json",
    )
    parser.add_argument("--sample-size", type=int, default=500)
    args = parser.parse_args()

    frame = load_frame(args.data)
    train_end = int(len(frame) * 0.70)
    val_end = int(len(frame) * 0.85)

    extractor = RollingFeatureExtractor(window_seconds=300)
    train_normal_times = frame.iloc[:train_end]
    train_normal_times = train_normal_times.loc[
        train_normal_times["label"] == 0, "timestamp"
    ]
    extractor.fit_time_statistics(train_normal_times)
    features = extractor.transform(frame, reset=True)

    service = MLService(str(args.model))
    service.load()
    test_features = features.iloc[val_end:][FEATURE_COLUMNS]
    sample = test_features.head(max(1, min(args.sample_size, len(test_features))))

    # TreeExplainer explains the IsolationForest model output. The production
    # anomaly score additionally negates decision_function and applies a tuned
    # threshold, so these values are feature-attribution evidence rather than
    # a decomposition of the final risk score.
    explainer = shap.TreeExplainer(service.model)
    explanation = explainer(sample)
    values = np.asarray(explanation.values)
    reduce_axes = tuple(range(max(values.ndim - 1, 1)))
    mean_abs = np.abs(values).mean(axis=reduce_axes)
    mean_abs = np.asarray(mean_abs).reshape(-1)

    ranking = sorted(
        (
            {"feature": feature, "mean_abs_shap": float(value)}
            for feature, value in zip(FEATURE_COLUMNS, mean_abs, strict=True)
        ),
        key=lambda item: item["mean_abs_shap"],
        reverse=True,
    )

    payload = {
        "model_version": service.VERSION,
        "sample_size": int(len(sample)),
        "scope": "IsolationForest model output; not the final risk score",
        "features": ranking,
    }

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    print(json.dumps(payload, indent=2))
    print(f"Saved: {args.output}")


if __name__ == "__main__":
    main()
