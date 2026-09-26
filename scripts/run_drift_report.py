"""Generate an Evidently feature-drift report for the SOC detector."""

from __future__ import annotations

import argparse
from pathlib import Path

import pandas as pd
from evidently import DataDefinition, Dataset, Report
from evidently.presets import DataDriftPreset

from ml.feature_extractor import FEATURE_COLUMNS, RollingFeatureExtractor
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
        "--html",
        type=Path,
        default=ROOT / "ml" / "reports" / "drift_report.html",
    )
    parser.add_argument(
        "--json",
        type=Path,
        default=ROOT / "ml" / "reports" / "drift_report.json",
    )
    args = parser.parse_args()

    frame = load_frame(args.data)
    train_end = int(len(frame) * 0.70)
    val_end = int(len(frame) * 0.85)

    extractor = RollingFeatureExtractor(window_seconds=300)
    train_normal = frame.iloc[:train_end]
    train_normal = train_normal.loc[train_normal["label"] == 0, "timestamp"]
    extractor.fit_time_statistics(train_normal)
    features = extractor.transform(frame, reset=True)

    labels = frame["label"].astype(int).reset_index(drop=True)
    reference = features.iloc[:train_end].loc[labels.iloc[:train_end] == 0]
    current = features.iloc[val_end:]

    definition = DataDefinition(numerical_columns=FEATURE_COLUMNS)
    reference_ds = Dataset.from_pandas(
        reference.reset_index(drop=True),
        data_definition=definition,
    )
    current_ds = Dataset.from_pandas(
        current.reset_index(drop=True),
        data_definition=definition,
    )

    report = Report(
        [DataDriftPreset(columns=FEATURE_COLUMNS)],
        include_tests=True,
        model_id="soc-isolation-forest",
        reference_id="chronological-training-normal",
        dataset_id="soc-events",
    )
    snapshot = report.run(current_ds, reference_ds)

    args.html.parent.mkdir(parents=True, exist_ok=True)
    snapshot.save_html(str(args.html))
    args.json.write_text(snapshot.json(), encoding="utf-8")

    print(f"Reference rows: {len(reference)}")
    print(f"Current rows:   {len(current)}")
    print(f"HTML report:    {args.html}")
    print(f"JSON report:    {args.json}")


if __name__ == "__main__":
    main()
