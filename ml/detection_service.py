"""Real-time event detection service combining rolling features and ML scoring."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from threading import RLock
from time import perf_counter

import pandas as pd

from ml.feature_extractor import FEATURE_COLUMNS, RollingFeatureExtractor
from ml.ml_service import MLService
from ml.risk_scorer import score_risk


@dataclass
class DetectionResult:
    detected: bool
    anomaly_score: float
    risk_score: float
    severity: str
    latency_ms: float
    features: dict
    feature_columns: list[str]

    def to_dict(self) -> dict:
        return asdict(self)


class DetectionService:
    """Long-lived detector for event-driven inference."""

    VERSION = "2.1.0"

    def __init__(self, artifact_path: str = "ml/models/isolation_forest.joblib"):
        self.model = MLService(artifact_path)
        self.model.load()

        stats = self.model.feature_stats
        self.extractor = RollingFeatureExtractor(window_seconds=300)
        self.extractor.time_mean = float(stats.get("time_mean", 12.0))
        self.extractor.time_std = float(stats.get("time_std", 4.0)) or 1.0
        self._lock = RLock()

    @staticmethod
    def validate_event(event: dict) -> None:
        required = {
            "timestamp",
            "source_ip",
            "destination_ip",
            "source_port",
            "destination_port",
            "protocol",
            "bytes_in",
            "bytes_out",
            "failed_logins",
            "country",
            "latitude",
            "longitude",
        }
        missing = sorted(required - set(event))
        if missing:
            raise ValueError(f"Missing required event fields: {', '.join(missing)}")

        numeric_fields = (
            "source_port",
            "destination_port",
            "bytes_in",
            "bytes_out",
            "failed_logins",
            "latitude",
            "longitude",
        )
        for field in numeric_fields:
            value = event[field]
            if isinstance(value, bool):
                raise ValueError(f"Event field '{field}' must be numeric")
            try:
                float(value)
            except (TypeError, ValueError) as exc:
                raise ValueError(f"Event field '{field}' must be numeric") from exc

        latitude = float(event["latitude"])
        longitude = float(event["longitude"])
        if not -90.0 <= latitude <= 90.0:
            raise ValueError("Event field 'latitude' must be between -90 and 90")
        if not -180.0 <= longitude <= 180.0:
            raise ValueError("Event field 'longitude' must be between -180 and 180")

        for field in ("source_port", "destination_port", "failed_logins"):
            value = float(event[field])
            if value < 0 or not value.is_integer():
                raise ValueError(f"Event field '{field}' must be a non-negative integer")

    def analyze(self, event: dict) -> DetectionResult:
        start = perf_counter()
        self.validate_event(event)

        # The rolling extractor is stateful. Serialize feature-state mutation so\n        # concurrent HTTP/greenlet requests cannot corrupt or reorder the window.\n        with self._lock:\n            features = self.extractor.transform_event(event)\n            frame = pd.DataFrame([features], columns=FEATURE_COLUMNS)\n            scores, predictions = self.model.predict_scores(frame)\n
        anomaly_score = float(scores[0])
        detected = bool(predictions[0])
        risk = score_risk(anomaly_score, features)

        latency_ms = (perf_counter() - start) * 1000.0

        return DetectionResult(
            detected=detected,
            anomaly_score=round(anomaly_score, 6),
            risk_score=risk["risk_score"],
            severity=risk["severity"],
            latency_ms=round(latency_ms, 4),
            features=features,
            feature_columns=FEATURE_COLUMNS.copy(),
        )
