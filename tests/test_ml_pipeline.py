from __future__ import annotations

from datetime import datetime, timezone

import pandas as pd
import pytest

from app import create_app, socketio
from ml.feature_extractor import FEATURE_COLUMNS, RollingFeatureExtractor
from ml.ml_service import MLService


@pytest.fixture()
def sample_event() -> dict:
    return {
        "timestamp": datetime(2026, 1, 15, 12, 0, tzinfo=timezone.utc).isoformat(),
        "source_ip": "10.10.10.10",
        "destination_ip": "192.0.2.10",
        "source_port": 49152,
        "destination_port": 443,
        "protocol": "HTTPS",
        "bytes_in": 1000,
        "bytes_out": 500,
        "failed_logins": 0,
        "country": "US",
        "latitude": 40.7128,
        "longitude": -74.0060,
    }


def test_feature_extractor_returns_expected_schema(sample_event: dict) -> None:
    extractor = RollingFeatureExtractor(window_seconds=300)
    features = extractor.transform_event(sample_event)

    assert list(features) == FEATURE_COLUMNS
    assert all(isinstance(value, (int, float)) for value in features.values())
    assert all(pd.notna(value) for value in features.values())


def test_model_artifact_loads_and_exposes_expected_features() -> None:
    service = MLService("ml/models/isolation_forest.joblib")
    service.load()

    assert service.model is not None
    assert service.feature_columns == FEATURE_COLUMNS
    assert 0.0 < service.threshold
    assert service.VERSION.startswith("2.")


def test_health_endpoint() -> None:
    app = create_app()
    client = app.test_client()

    response = client.get("/api/ml/health")

    assert response.status_code == 200
    payload = response.get_json()
    assert payload["status"] == "ready"
    assert payload["features"] == FEATURE_COLUMNS
    assert "threshold" in payload


def test_event_endpoint_scores_and_returns_detection(monkeypatch, sample_event: dict) -> None:
    app = create_app()
    client = app.test_client()

    monkeypatch.setattr("app.services.event_processing.threat_score", lambda _ip: 0)
    monkeypatch.setattr("app.services.event_processing.insert_log", lambda *_args: None)

    response = client.post("/api/ml/events", json=sample_event)

    assert response.status_code == 200
    payload = response.get_json()
    assert payload["model_version"].startswith("2.")
    assert payload["event"]["source_ip"] == sample_event["source_ip"]
    assert set(payload["detection"]["features"]) == set(FEATURE_COLUMNS)
    assert isinstance(payload["detection"]["detected"], bool)
    assert payload["detection"]["latency_ms"] >= 0


def test_event_validation_reports_missing_fields() -> None:
    app = create_app()
    client = app.test_client()

    response = client.post(
        "/api/ml/events",
        json={
            "timestamp": "2026-01-15T12:00:00+00:00",
            "source_ip": "10.10.10.10",
            "destination_port": 443,
            "protocol": "HTTPS",
            "bytes_in": 1000,
            "bytes_out": 500,
            "failed_logins": 0,
            "latitude": 40.7128,
            "longitude": -74.0060,
        },
    )

    assert response.status_code == 400
    assert "destination_ip" in response.get_json()["error"]
    assert response.get_json()["request_id"]


def test_socketio_test_client_can_connect() -> None:
    app = create_app()
    client = socketio.test_client(app, flask_test_client=app.test_client())

    assert client.is_connected()
    client.disconnect()
