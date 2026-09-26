"""Promote an MLflow model version only when governance gates pass."""

from __future__ import annotations

import argparse
import os

import mlflow
from mlflow import MlflowClient

from ml.governance import evaluate_candidate_against_champion


def _run_metrics(client: MlflowClient, run_id: str) -> dict:
    run = client.get_run(run_id)
    return dict(run.data.metrics)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--model",
        default=os.getenv("MLFLOW_MODEL_NAME", "soc-isolation-forest"),
    )
    parser.add_argument("--alias", default="champion")
    parser.add_argument(
        "--version",
        help="Explicit version; defaults to latest numeric version",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="Bypass quality gates. Intended only for documented emergency rollback.",
    )
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

    candidate = client.get_model_version(args.model, version)
    candidate_metrics = _run_metrics(client, candidate.run_id)

    champion_metrics = None
    try:
        champion = client.get_model_version_by_alias(args.model, args.alias)
        if str(champion.version) != str(version):
            champion_metrics = _run_metrics(client, champion.run_id)
    except Exception:
        champion = None

    passed, reasons = evaluate_candidate_against_champion(
        candidate_metrics,
        champion_metrics,
    )
    if not passed and not args.force:
        for reason in reasons:
            print(f"REJECT: {reason}")
        raise SystemExit("candidate failed promotion gates")

    client.set_registered_model_alias(args.model, args.alias, version)
    resolved = client.get_model_version_by_alias(args.model, args.alias)
    print(
        f"{args.model}@{args.alias} -> version {resolved.version} "
        f"(run_id={resolved.run_id}, forced={args.force})"
    )


if __name__ == "__main__":
    main()
