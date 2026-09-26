"""Dashboard and authentication routes."""

from __future__ import annotations

import csv
import datetime
import io
from functools import wraps

import jwt
from flask import (
    Blueprint,
    Response,
    current_app,
    flash,
    jsonify,
    redirect,
    render_template,
    request,
    send_file,
    session,
)

from app.models.auth import register_user, verify_user
from app.models.database import get_logs
from app.services.report_service import generate_report


realtime_bp = Blueprint("realtime", __name__)


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if "user" not in session:
            return redirect("/login")
        return view(*args, **kwargs)

    return wrapped


def admin_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if session.get("role") != "Admin":
            return jsonify({"error": "administrator required"}), 403
        return view(*args, **kwargs)

    return wrapped


@realtime_bp.route("/")
@login_required
def home():
    logs = get_logs()
    brute_force_count = sum(
        1 for log in logs
        if "brute_force" in log[1].lower() or "failed login" in log[1].lower()
    )
    ddos_count = sum(
        1 for log in logs
        if "ddos" in log[1].lower() or "high traffic" in log[1].lower()
    )
    normal_count = sum(
        1 for log in logs
        if "normal" in log[1].lower() or "successful login" in log[1].lower()
    )
    risk_trend = [log[2] for log in logs[::-1]]

    return render_template(
        "dashboard.html",
        logs=logs,
        risk=risk_trend[-1] if risk_trend else 0,
        threat=logs[0][3] if logs else 0,
        brute_force_count=brute_force_count,
        ddos_count=ddos_count,
        normal_count=normal_count,
        risk_trend=risk_trend,
    )


@realtime_bp.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        role = verify_user(request.form.get("username", ""), request.form.get("password", ""))
        if role:
            session.clear()
            session["user"] = request.form["username"].strip()
            session["role"] = role
            flash("Login successful", "success")
            return redirect("/")
        flash("Invalid username or password", "danger")
    return render_template("login.html")


@realtime_bp.route("/register", methods=["GET", "POST"])
@admin_required
def register():
    if request.method == "POST":
        try:
            register_user(
                request.form.get("username", ""),
                request.form.get("password", ""),
                request.form.get("role", "Analyst"),
            )
        except ValueError as exc:
            return jsonify({"error": str(exc)}), 400
        return redirect("/")
    return render_template("register.html")


@realtime_bp.route("/logout")
def logout():
    session.clear()
    return redirect("/login")


@realtime_bp.route("/admin")
@admin_required
def admin_panel():
    return render_template("admin.html")


@realtime_bp.route("/api/login", methods=["POST"])
def api_login():
    body = request.get_json(silent=True) or {}
    username = body.get("username")
    password = body.get("password")
    if not username or not password:
        return jsonify({"error": "username and password are required"}), 400

    role = verify_user(username, password)
    if not role:
        return jsonify({"error": "Invalid credentials"}), 401

    now = datetime.datetime.now(datetime.timezone.utc)
    token = jwt.encode(
        {
            "sub": username,
            "role": role,
            "iat": now,
            "exp": now + datetime.timedelta(hours=1),
            "iss": "soc-platform",
        },
        current_app.config["JWT_SECRET_KEY"],
        algorithm="HS256",
    )
    return jsonify({"token": token, "expires_in": 3600})


@realtime_bp.route("/api/logs")
def api_logs():
    token = request.headers.get("Authorization", "")
    if not token.startswith("Bearer "):
        return jsonify({"error": "Bearer token required"}), 401

    try:
        jwt.decode(
            token[7:],
            current_app.config["JWT_SECRET_KEY"],
            algorithms=["HS256"],
            issuer="soc-platform",
        )
        return jsonify({"logs": get_logs()})
    except jwt.ExpiredSignatureError:
        return jsonify({"error": "Token expired"}), 401
    except jwt.PyJWTError:
        return jsonify({"error": "Invalid token"}), 401


@realtime_bp.route("/report")
@login_required
def report():
    path = generate_report()
    return send_file(path, as_attachment=True, download_name="soc_report.pdf")


@realtime_bp.route("/export_csv")
@login_required
def export_csv():
    logs = get_logs(limit=None)
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["Log", "Risk Score", "Threat Score"])
    for log in logs:
        writer.writerow([log[1], log[2], log[3]])

    return Response(
        output.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment; filename=analytics.csv"},
    )


@realtime_bp.route("/favicon.ico")
def favicon():
    from flask import send_from_directory

    return send_from_directory("static", "favicon.ico")
