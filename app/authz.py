"""JWT authorization helpers for SOC APIs."""

from __future__ import annotations

from functools import wraps

import jwt
from flask import current_app, g, jsonify, request


def _decode_bearer() -> dict:
    header = request.headers.get("Authorization", "")
    if not header.startswith("Bearer "):
        raise PermissionError("Bearer token required")

    try:
        return jwt.decode(
            header[7:],
            current_app.config["JWT_SECRET_KEY"],
            algorithms=["HS256"],
            issuer="soc-platform",
            options={"require": ["sub", "role", "iat", "exp", "iss"]},
        )
    except jwt.ExpiredSignatureError as exc:
        raise PermissionError("Token expired") from exc
    except jwt.PyJWTError as exc:
        raise PermissionError("Invalid token") from exc


def api_roles_required(*roles: str):
    allowed = set(roles)

    def decorator(view):
        @wraps(view)
        def wrapped(*args, **kwargs):
            try:
                claims = _decode_bearer()
            except PermissionError as exc:
                return jsonify({"error": str(exc)}), 401

            role = str(claims.get("role", ""))
            if allowed and role not in allowed:
                return jsonify({"error": "forbidden"}), 403

            g.api_user = str(claims["sub"])
            g.api_role = role
            return view(*args, **kwargs)

        return wrapped

    return decorator
