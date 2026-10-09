import json
import os
import secrets

from flask import (Flask, Response, abort, flash, jsonify, redirect, render_template,
                   request, session, url_for)

import config
from database.db import init_db
from services import alert_service, incident_service


def create_app(db_path=None):
    app = Flask(__name__)
    app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY") or secrets.token_hex(16)
    app.config["MAX_CONTENT_LENGTH"] = 2 * 1024 * 1024  # 2 MB upload cap
    app.config["DB_PATH"] = db_path or config.DB_PATH
    db = app.config["DB_PATH"]

    init_db(db)
    if alert_service.count_events(db) == 0 and os.path.exists(config.LOG_PATH):
        alert_service.ingest_file(config.LOG_PATH, db)

    # ---- CSRF protection for all POST forms -------------------------------------------
    @app.before_request
    def csrf_protect():
        if request.method == "POST":
            token = session.get("csrf_token")
            if not token or token != request.form.get("csrf_token"):
                abort(400, "Invalid CSRF token")

    @app.template_filter("ts")
    def format_timestamp(value):
        """2026-10-09T10:45:00 -> 2026-10-09 10:45:00 (em dash when empty)."""
        return str(value).replace("T", " ") if value else "—"

    @app.context_processor
    def inject_globals():
        if "csrf_token" not in session:
            session["csrf_token"] = secrets.token_hex(16)
        return {"csrf_token": session["csrf_token"], "statuses": config.STATUSES}

    # ---- Pages -------------------------------------------------------------------------
    @app.route("/")
    def dashboard():
        stats = alert_service.get_stats(db)
        recent = alert_service.list_alerts(db)[:8]
        return render_template("dashboard.html", stats=stats, recent=recent)

    @app.route("/alerts")
    def alerts():
        filters = {k: request.args.get(k, "").strip() for k in ("severity", "source_ip", "rule", "status", "date")}
        rows = alert_service.list_alerts(db, **filters)
        return render_template("alerts.html", alerts=rows, filters=filters,
                               rules=alert_service.distinct_rules(db))

    @app.route("/alerts/<int:alert_id>")
    def alert_detail(alert_id):
        alert = alert_service.get_alert(alert_id, db)
        if not alert:
            abort(404)
        return render_template("alert_detail.html", alert=alert)

    @app.route("/alerts/<int:alert_id>/update", methods=["POST"])
    def alert_update(alert_id):
        ok, message = incident_service.update_incident(
            alert_id, request.form.get("status", ""), request.form.get("assigned_to", ""),
            request.form.get("notes", ""), db)
        flash(message, "success" if ok else "danger")
        return redirect(url_for("alert_detail", alert_id=alert_id))

    @app.route("/alerts/<int:alert_id>/report.md")
    def alert_report(alert_id):
        alert = alert_service.get_alert(alert_id, db)
        if not alert:
            abort(404)
        return Response(incident_service.build_report(alert), mimetype="text/markdown",
                        headers={"Content-Disposition": f"attachment; filename=alert_{alert_id}_report.md"})

    @app.route("/incidents")
    def incidents():
        status = request.args.get("status", "").strip()
        return render_template("incidents.html", incidents=incident_service.list_incidents(db, status),
                               current=status)

    # ---- Log ingestion -----------------------------------------------------------------
    @app.route("/ingest", methods=["POST"])
    def ingest():
        upload = request.files.get("logfile")
        try:
            if upload and upload.filename:
                data = json.load(upload.stream)
                if not isinstance(data, list):
                    raise ValueError("log file must contain a JSON list of events")
                summary = alert_service.ingest(data, db)
            else:
                summary = alert_service.ingest_file(config.LOG_PATH, db)
            flash(f"Ingested {summary['received']} records: {summary['valid']} valid, "
                  f"{summary['invalid']} invalid, {summary['new_alerts']} new alert(s).", "success")
        except (ValueError, json.JSONDecodeError) as exc:
            flash(f"Could not ingest logs: {exc}", "danger")
        return redirect(request.referrer or url_for("dashboard"))

    @app.route("/api/stats")
    def api_stats():
        return jsonify(alert_service.get_stats(db))

    return app


if __name__ == "__main__":
    create_app().run(host="127.0.0.1", port=5000, debug=False)
