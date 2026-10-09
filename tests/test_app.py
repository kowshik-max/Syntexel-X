import re

import pytest

import config
from app import create_app
from services import alert_service, incident_service


@pytest.fixture()
def client(tmp_path):
    app = create_app(str(tmp_path / "test.db"))
    app.config["TESTING"] = True
    return app.test_client(), app.config["DB_PATH"]


def csrf(client):
    html = client.get("/").get_data(as_text=True)
    return re.search(r'name="csrf_token" value="([^"]+)"', html).group(1)


def test_pages_load(client):
    c, _ = client
    for path in ("/", "/alerts", "/incidents", "/alerts/1", "/api/stats"):
        assert c.get(path).status_code == 200, path
    assert c.get("/alerts/99999").status_code == 404


def test_sample_logs_produce_expected_alerts(client):
    _, db = client
    rules = {a["rule_name"] for a in alert_service.list_alerts(db)}
    assert {"Repeated Failed Logins", "Success After Repeated Failures",
            "Suspicious Event Combination", "Invalid Log Record"} <= rules


def test_ingest_is_idempotent(client):
    _, db = client
    before = len(alert_service.list_alerts(db))
    summary = alert_service.ingest_file(config.LOG_PATH, db)
    assert summary["new_alerts"] == 0
    assert len(alert_service.list_alerts(db)) == before


def test_filter_by_severity(client):
    c, db = client
    rows = alert_service.list_alerts(db, severity="Critical")
    assert rows and {r["severity"] for r in rows} == {"Critical"}
    html = c.get("/alerts?severity=Critical").get_data(as_text=True)
    assert "badge sev-critical" in html
    assert "badge sev-low" not in html


def test_update_requires_csrf(client):
    c, _ = client
    assert c.post("/alerts/1/update", data={"status": "Resolved"}).status_code == 400


def test_update_incident_status_and_notes(client):
    c, db = client
    token = csrf(c)
    c.post("/alerts/1/update", data={"csrf_token": token, "status": "Investigating",
                                     "assigned_to": "analyst1", "notes": "Checking VPN logs"})
    alert = alert_service.get_alert(1, db)
    assert alert["status"] == "Investigating"
    assert alert["notes"] == "Checking VPN logs"


def test_invalid_status_rejected(client):
    _, db = client
    ok, _ = incident_service.update_incident(1, "Hacked", db_path=db)
    assert ok is False


def test_report_download(client):
    c, _ = client
    resp = c.get("/alerts/1/report.md")
    assert resp.status_code == 200
    assert b"Recommended actions" in resp.data
