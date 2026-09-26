"""Download the exact persisted detector bundle behind an MLflow model alias."""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import shutil

import mlflow
from mlflow import MlflowClient


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--model", default=os.getenv("MLFLOW_MODEL_NAME", "soc-isolation-forest"))
    parser.add_argument("--alias", default="champion")
    parser.add_argument("--output", default="ml/models/isolation_forest.joblib")
    args = parser.parse_args()

    tracking_uri = os.getenv("MLFLOW_TRACKING_URI")
    if not tracking_uri:
        raise SystemExit("MLFLOW_TRACKING_URI is required")

    mlflow.set_tracking_uri(tracking_uri)
    client = MlflowClient()
    version = client.get_model_version_by_alias(args.model, args.alias)

    downloaded = client.download_artifacts(
        version.run_id,
        "model_bundle/isolation_forest.joblib",
    )
    destination = Path(args.output)
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(downloaded, destination)

    print(
        f"Exported {args.model}@{args.alias} version {version.version} "
        f"to {destination}"
    )


if __name__ == "__main__":
    main()
