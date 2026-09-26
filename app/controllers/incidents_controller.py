"""SOC incident workflow API."""

from __future__ import annotations

from flask import Blueprint, g, jsonify, request

from app.authz import api_roles_required
from app.models.database import (
    add_incident_note,
    assign_incident,
    get_incident,
    get_incident_audit,
    get_incident_notes,
    get_incidents,
    transition_incident,
)


incidents_bp = Blueprint("incidents", __name__, url_prefix="/api/incidents")


def _serialize(value):
    if isinstance(value, list):
        return [_serialize(item) for item in value]
    if isinstance(value, dict):
        return {key: _serialize(item) for key, item in value.items()}
    if hasattr(value, "isoformat"):
        return value.isoformat()
    return value


@incidents_bp.route("", methods=["GET"])
@api_roles_required("Analyst", "Admin")
def list_incidents():
    try:
        limit = int(request.args.get("limit", "100"))
    except ValueError:
        return jsonify({"error": "limit must be an integer"}), 400
    return jsonify({"incidents": _serialize(get_incidents(limit))})


@incidents_bp.route("/<incident_id>", methods=["GET"])
@api_roles_required("Analyst", "Admin")
def incident_detail(incident_id: str):
    incident = get_incident(incident_id)
    if incident is None:
        return jsonify({"error": "incident not found"}), 404

    return jsonify(
        {
            "incident": _serialize(incident),
            "notes": _serialize(get_incident_notes(incident_id)),
            "audit": _serialize(get_incident_audit(incident_id)),
        }
    )


@incidents_bp.route("/<incident_id>/status", methods=["PATCH"])
@api_roles_required("Analyst", "Admin")
def update_status(incident_id: str):
    body = request.get_json(silent=True) or {}
    status = body.get("status")
    if not isinstance(status, str):
        return jsonify({"error": "status is required"}), 400

    try:
        incident = transition_incident(incident_id, status, g.api_user)
    except KeyError:
        return jsonify({"error": "incident not found"}), 404
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 409
    except RuntimeError as exc:
        return jsonify({"error": str(exc)}), 409

    return jsonify({"incident": _serialize(incident)})


@incidents_bp.route("/<incident_id>/assignment", methods=["PATCH"])
@api_roles_required("Analyst", "Admin")
def update_assignment(incident_id: str):
    body = request.get_json(silent=True) or {}
    assignee = body.get("assignee")
    if assignee is not None and not isinstance(assignee, str):
        return jsonify({"error": "assignee must be a string or null"}), 400

    # Analysts may assign work to themselves; Admins may assign any analyst.
    if g.api_role != "Admin" and assignee not in {None, g.api_user}:
        return jsonify({"error": "analysts may only assign incidents to themselves"}), 403

    try:
        incident = assign_incident(incident_id, assignee, g.api_user)
    except KeyError:
        return jsonify({"error": "incident not found"}), 404

    return jsonify({"incident": _serialize(incident)})


@incidents_bp.route("/<incident_id>/notes", methods=["POST"])
@api_roles_required("Analyst", "Admin")
def create_note(incident_id: str):
    body = request.get_json(silent=True) or {}
    note = body.get("note")
    if not isinstance(note, str):
        return jsonify({"error": "note is required"}), 400

    try:
        created = add_incident_note(incident_id, g.api_user, note)
    except KeyError:
        return jsonify({"error": "incident not found"}), 404
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400

    return jsonify({"note": _serialize(created)}), 201
