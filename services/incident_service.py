"""Investigation tracking and incident report generation."""
from datetime import datetime

import config
from database.db import get_conn
from services.alert_service import SEVERITY_SQL


def update_incident(alert_id, status, assigned_to="", notes="", db_path=None):
    """Validate and save investigation state. Returns (ok, message)."""
    if status not in config.STATUSES:
        return False, "Invalid status."
    assigned_to = (assigned_to or "").strip()
    notes = (notes or "").strip()
    if len(assigned_to) > 80:
        return False, "Assignee name is too long (max 80 characters)."
    if len(notes) > 4000:
        return False, "Notes are too long (max 4000 characters)."
    conn = get_conn(db_path)
    try:
        cur = conn.execute(
            "UPDATE incidents SET status = ?, assigned_to = ?, notes = ?, updated_at = ? WHERE alert_id = ?",
            (status, assigned_to, notes, datetime.now().isoformat(timespec="seconds"), alert_id),
        )
        conn.commit()
        if cur.rowcount == 0:
            return False, "Alert not found."
        return True, "Investigation updated."
    finally:
        conn.close()


def list_incidents(db_path=None, status=""):
    sql = (
        "SELECT i.*, a.rule_name, a.severity, a.source_ip, a.first_seen FROM incidents i "
        "JOIN alerts a ON a.id = i.alert_id"
    )
    params = []
    if status:
        sql += " WHERE i.status = ?"
        params.append(status)
    sql += f" ORDER BY i.updated_at DESC, {SEVERITY_SQL} DESC"
    conn = get_conn(db_path)
    try:
        return [dict(r) for r in conn.execute(sql, params).fetchall()]
    finally:
        conn.close()


def build_report(alert):
    """Markdown incident report for one alert (alert dict from get_alert)."""
    lines = [
        f"# Incident Report - Alert #{alert['id']}: {alert['rule_name']}",
        "",
        f"_Generated {datetime.now().isoformat(timespec='seconds')} by Syntexel X (learning prototype)._",
        "",
        "## 1. Finding",
        alert["description"],
        "",
        "## 2. Affected asset",
        f"Account(s): {alert['username'] or 'n/a'} | Source IP: {alert['source_ip']}",
        "",
        "## 3. Evidence",
        f"- Events: {alert['event_count']}",
        f"- First seen: {alert['first_seen'] or 'n/a'}",
        f"- Last seen: {alert['last_seen'] or 'n/a'}",
        "",
        "| Timestamp | Event | User | Source IP |",
        "|---|---|---|---|",
    ]
    for e in alert["evidence"][:50]:
        if "errors" in e:
            lines.append(f"| - | invalid record | - | {', '.join(e['errors'])} |")
        else:
            lines.append(f"| {e['timestamp']} | {e['event_type']} | {e['username']} | {e['source_ip']} |")
    lines += [
        "",
        "## 4. Severity",
        f"{alert['severity']} (per this lab's defined rules; thresholds are starting values, not standards).",
        "",
        "## 5. Potential impact",
        alert["impact"] or "n/a",
        "",
        "## 6. Recommended actions",
        alert["recommended_action"] or "n/a",
        "",
        "## 7. MITRE ATT&CK (possible match, not a confirmed attack)",
        f"{alert['mitre_id'] or 'None'} - {alert['mitre_name'] or 'n/a'}",
        "",
        "## 8. Status",
        f"{alert['status']} | Assigned to: {alert['assigned_to'] or 'unassigned'}",
        "",
        "Analyst notes:",
        alert["notes"] or "_none yet_",
        "",
        "## 9. Retest",
        "After remediation, re-run the detection and verify the suspicious pattern no longer continues.",
        "",
    ]
    return "\n".join(lines)
