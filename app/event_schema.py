"""Versioned validation for external SOC event envelopes."""

from __future__ import annotations

import datetime as dt
import ipaddress
import math


EVENT_SCHEMA_VERSION = "1"

_REQUIRED = {
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


def validate_event_v1(event: dict) -> None:
    if not isinstance(event, dict):
        raise TypeError("event must be an object")

    missing = sorted(_REQUIRED - set(event))
    if missing:
        raise ValueError(f"Missing required event fields: {', '.join(missing)}")

    try:
        timestamp = dt.datetime.fromisoformat(str(event["timestamp"]).replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError("timestamp must be ISO-8601") from exc
    if timestamp.tzinfo is None:
        raise ValueError("timestamp must include a timezone")

    for field in ("source_ip", "destination_ip"):
        try:
            ipaddress.ip_address(str(event[field]))
        except ValueError as exc:
            raise ValueError(f"{field} must be a valid IPv4 or IPv6 address") from exc

    for field in ("source_port", "destination_port"):
        value = event[field]
        if isinstance(value, bool):
            raise TypeError(f"{field} must be an integer")
        try:
            parsed = int(value)
        except (TypeError, ValueError) as exc:
            raise TypeError(f"{field} must be an integer") from exc
        if parsed < 0 or parsed > 65535:
            raise ValueError(f"{field} must be between 0 and 65535")

    for field in ("bytes_in", "bytes_out", "failed_logins"):
        value = event[field]
        if isinstance(value, bool):
            raise TypeError(f"{field} must be a non-negative number")
        try:
            parsed = float(value)
        except (TypeError, ValueError) as exc:
            raise TypeError(f"{field} must be a non-negative number") from exc
        if not math.isfinite(parsed) or parsed < 0:
            raise ValueError(f"{field} must be a finite non-negative number")
        if field == "failed_logins" and not parsed.is_integer():
            raise ValueError("failed_logins must be an integer")

    protocol = str(event["protocol"]).strip()
    if not protocol or len(protocol) > 32:
        raise ValueError("protocol must contain 1-32 characters")

    country = str(event["country"]).strip()
    if len(country) > 64:
        raise ValueError("country must be 64 characters or fewer")

    for field, minimum, maximum in (
        ("latitude", -90.0, 90.0),
        ("longitude", -180.0, 180.0),
    ):
        try:
            value = float(event[field])
        except (TypeError, ValueError) as exc:
            raise TypeError(f"{field} must be numeric") from exc
        if not math.isfinite(value) or not minimum <= value <= maximum:
            raise ValueError(f"{field} must be between {minimum:g} and {maximum:g}")
