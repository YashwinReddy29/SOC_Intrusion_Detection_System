"""User authentication helpers."""

from __future__ import annotations

import bcrypt

from app.models.database import create_user, get_user_credentials


ALLOWED_ROLES = {"Admin", "Analyst"}


def register_user(username: str, password: str, role: str = "Analyst") -> bool:
    username = (username or "").strip()
    role = (role or "").strip()

    if not 3 <= len(username) <= 128:
        raise ValueError("username must contain 3-128 characters")
    if len(password or "") < 12:
        raise ValueError("password must contain at least 12 characters")
    if role not in ALLOWED_ROLES:
        raise ValueError("invalid role")

    hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
    create_user(username, hashed, role)
    return True


def verify_user(username: str, password: str) -> str | None:
    if not username or not password:
        return None
    user = get_user_credentials(username.strip())
    if user is None:
        return None

    password_hash, role = user
    if bcrypt.checkpw(password.encode(), password_hash):
        return role
    return None
