"""Ingest logs, run detection, persist alerts, and query them for the dashboard."""
import json
from datetime import datetime

from database.db import get_conn
from detection.detection_rules import run_all
from detection.log_parser import load_log_file, parse_events

SEVERITY_SQL = "CASE a.severity WHEN 'Critical' THEN 4 WHEN 'High' THEN 3 WHEN 'Medium' THEN 2 ELSE 1 END"
OPEN_STATUSES = ("New", "Investigating", "Escalated")


def _now():
    return datetime.now().isoformat(timespec="seconds")


def _store_events(conn, events):
    conn.executemany(
        "INSERT OR IGNORE INTO event_logs (timestamp, event_type, username, source_ip, status) "
        "VALUES (:timestamp, :event_type, :username, :source_ip, :status)",
        events,
    )


def _load_events(conn):
    rows = conn.execute(
        "SELECT timestamp, event_type, username, source_ip, status FROM event_logs ORDER BY timestamp"
    ).fetchall()
    return [dict(r) for r in rows]


def ingest(raw_events, db_path=None):
    """Validate + store events, run all rules over everything stored, persist new alerts.

    Re-ingesting the same data is idempotent: events and alerts are de-duplicated, and
    existing investigation notes/status are never overwritten.
    """
    valid, invalid = parse_events(raw_events)
    conn = get_conn(db_path)
    try:
        _store_events(conn, valid)
        alerts = run_all(_load_events(conn), invalid)
        new_alerts = 0
        for a in alerts:
            key = f"{a['rule_name']}|{a['source_ip']}|{a['first_seen']}|{a['username']}|{a['event_count']}"
            cur = conn.execute(
                "INSERT OR IGNORE INTO alerts (rule_name, source_ip, username, severity, description, impact, "
                "recommended_action, mitre_id, mitre_name, event_count, first_seen, last_seen, evidence_json, "
                "dedupe_key, created_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (a["rule_name"], a["source_ip"], a["username"], a["severity"], a["description"], a["impact"],
                 a["recommended_action"], a["mitre_id"], a["mitre_name"], a["event_count"], a["first_seen"],
                 a["last_seen"], json.dumps(a["evidence"]), key, _now()),
            )
            if cur.rowcount:
                # "New" means queued for triage - a rule firing is not a confirmed incident.
                conn.execute(
                    "INSERT INTO incidents (alert_id, status, updated_at) VALUES (?, 'New', ?)",
                    (cur.lastrowid, _now()),
                )
                new_alerts += 1
        conn.commit()
        return {
            "received": len(raw_events),
            "valid": len(valid),
            "invalid": len(invalid),
            "alerts_detected": len(alerts),
            "new_alerts": new_alerts,
        }
    finally:
        conn.close()


def ingest_file(path, db_path=None):
    return ingest(load_log_file(path), db_path)


def count_events(db_path=None):
    conn = get_conn(db_path)
    try:
        return conn.execute("SELECT COUNT(*) FROM event_logs").fetchone()[0]
    finally:
        conn.close()


def list_alerts(db_path=None, severity="", source_ip="", rule="", status="", date=""):
    sql = (
        "SELECT a.*, i.status, i.assigned_to FROM alerts a JOIN incidents i ON i.alert_id = a.id WHERE 1=1"
    )
    params = []
    if severity:
        sql += " AND a.severity = ?"
        params.append(severity)
    if source_ip:
        sql += " AND a.source_ip LIKE ?"
        params.append(f"%{source_ip}%")
    if rule:
        sql += " AND a.rule_name = ?"
        params.append(rule)
    if status:
        sql += " AND i.status = ?"
        params.append(status)
    if date:
        sql += " AND a.first_seen LIKE ?"
        params.append(f"{date}%")
    sql += f" ORDER BY {SEVERITY_SQL} DESC, a.first_seen DESC"
    conn = get_conn(db_path)
    try:
        return [dict(r) for r in conn.execute(sql, params).fetchall()]
    finally:
        conn.close()


def get_alert(alert_id, db_path=None):
    conn = get_conn(db_path)
    try:
        row = conn.execute(
            "SELECT a.*, i.status, i.assigned_to, i.notes, i.updated_at "
            "FROM alerts a JOIN incidents i ON i.alert_id = a.id WHERE a.id = ?",
            (alert_id,),
        ).fetchone()
        if not row:
            return None
        alert = dict(row)
        alert["evidence"] = json.loads(alert.pop("evidence_json"))
        return alert
    finally:
        conn.close()


def distinct_rules(db_path=None):
    conn = get_conn(db_path)
    try:
        return [r[0] for r in conn.execute("SELECT DISTINCT rule_name FROM alerts ORDER BY rule_name")]
    finally:
        conn.close()


def get_stats(db_path=None):
    conn = get_conn(db_path)
    try:
        q = lambda sql, *p: conn.execute(sql, p).fetchall()
        total = q("SELECT COUNT(*) FROM alerts")[0][0]
        high = q("SELECT COUNT(*) FROM alerts WHERE severity IN ('High','Critical')")[0][0]
        open_inv = q(
            "SELECT COUNT(*) FROM incidents WHERE status IN ('New','Investigating','Escalated')"
        )[0][0]
        events = q("SELECT COUNT(*) FROM event_logs")[0][0]
        failed = q("SELECT COUNT(*) FROM event_logs WHERE event_type = 'login_failed'")[0][0]
        by_sev = {r[0]: r[1] for r in q("SELECT severity, COUNT(*) FROM alerts GROUP BY severity")}
        by_status = {r[0]: r[1] for r in q("SELECT status, COUNT(*) FROM incidents GROUP BY status")}
        trend = [
            {"hour": r[0], "count": r[1]}
            for r in q(
                "SELECT substr(first_seen, 1, 13) AS hour, COUNT(*) FROM alerts "
                "WHERE first_seen != '' GROUP BY hour ORDER BY hour"
            )
        ]
        top_ips = [
            {"ip": r[0], "failures": r[1]}
            for r in q(
                "SELECT source_ip, COUNT(*) c FROM event_logs WHERE event_type = 'login_failed' "
                "GROUP BY source_ip ORDER BY c DESC LIMIT 5"
            )
        ]
        return {
            "total_alerts": total,
            "high_alerts": high,
            "open_investigations": open_inv,
            "total_events": events,
            "failed_logins": failed,
            "by_severity": {s: by_sev.get(s, 0) for s in ("Critical", "High", "Medium", "Low")},
            "by_status": by_status,
            "trend": trend,
            "top_ips": top_ips,
        }
    finally:
        conn.close()
