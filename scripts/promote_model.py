"""Promote an MLflow model version by assigning an alias."""

from __future__ import annotations

import argparse
import os

import mlflow
from mlflow import MlflowClient


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--model", default=os.getenv("MLFLOW_MODEL_NAME", "soc-isolation-forest"))
    parser.add_argument("--alias", default="champion")
    parser.add_argument("--version", help="Explicit version; defaults to latest numeric version")
    args = parser.parse_args()

    tracking_uri = os.getenv("MLFLOW_TRACKING_URI")
    if not tracking_uri:
        raise SystemExit("MLFLOW_TRACKING_URI is required")

    mlflow.set_tracking_uri(tracking_uri)
    client = MlflowClient()

    version = args.version
    if version is None:
        versions = client.search_model_versions(f"name='{args.model}'")
        if not versions:
            raise SystemExit(f"No registered versions found for {args.model}")
        version = str(max(int(item.version) for item in versions))

    client.set_registered_model_alias(args.model, args.alias, version)
    resolved = client.get_model_version_by_alias(args.model, args.alias)
    print(
        f"{args.model}@{args.alias} -> version {resolved.version} "
        f"(run_id={resolved.run_id})"
    )


if __name__ == "__main__":
    main()
