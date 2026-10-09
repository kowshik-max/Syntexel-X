# Syntexel X - AI-Assisted SOC Threat Detection & Incident Response (learning prototype)

A Python/Flask SOC monitoring prototype. It ingests synthetic authentication logs, applies explainable
rule-based detection, stores alerts in SQLite, and lets an analyst investigate and report on them.

> Detection is rule-based. There is no trained ML model. Alerts are **indicators for investigation, not proof
> of compromise**. Thresholds are lab-defined starting values, not security standards.

## Features (all implemented and covered by tests)
- Log parser/validator (required fields, ISO timestamps, event types, IP format)
- Rules: repeated failed logins (5 in 5 min per IP), success after repeated failures (>=3),
  suspicious event combination (same IP triggers both), invalid-record data-quality alert
- Password-spraying vs brute-force distinction; MITRE ATT&CK possible mappings (T1110, T1110.003, T1078)
- Severity assignment, duplicate-alert suppression, idempotent re-ingest
- SQLite tables: `event_logs`, `alerts`, `incidents` (FK incidents.alert_id -> alerts.id)
- Dashboard (metrics, charts, recent activity), alert filters (severity, IP, rule, status, date), alert detail
  with evidence, investigation workflow (New / Investigating / Escalated / Resolved / False Positive)
- Markdown incident report download, CSRF protection on forms, upload size cap

## Run
```bash
python -m venv .venv
.venv\Scripts\Activate.ps1        # Windows (source .venv/bin/activate on macOS/Linux)
pip install -r requirements.txt
python -m pytest                  # 27 tests
python app.py                     # http://127.0.0.1:5000
```
The first start auto-ingests `data/sample_auth_logs.json`. Use **Ingest logs** to re-run or upload your own JSON list.

## Sample data scenarios
| Scenario | Expected result |
|---|---|
| Normal logins, logouts | No alert |
| bob: 2 typos then success | No alert (below thresholds) |
| 5 failures spread over 12 hours | No alert |
| test_user: 3 failures then success | Medium - success after failures |
| 198.51.100.23 -> admin: 8 failures then success | High + High + Critical (combination) |
| 203.0.113.45: 6 different accounts | High - possible password spraying |
| 3 malformed records | Low - invalid log record |

IPs are documentation-only ranges (RFC 5737). All data is synthetic.

## Limitations
No real-time ingestion, no authentication on the dashboard, no GeoIP/known-IP context, single-node SQLite.
It is a learning prototype, not a production SIEM.

## Layout
`app.py` routes - `detection/` parser, rules, severity, MITRE - `database/` schema + connection -
`services/` ingest, queries, reports - `templates/`, `static/` UI - `tests/` pytest suite
