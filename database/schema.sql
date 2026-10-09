CREATE TABLE IF NOT EXISTS event_logs (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp   TEXT NOT NULL,
    event_type  TEXT NOT NULL,
    username    TEXT NOT NULL,
    source_ip   TEXT NOT NULL,
    status      TEXT NOT NULL,
    UNIQUE (timestamp, event_type, username, source_ip, status)
);

CREATE TABLE IF NOT EXISTS alerts (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    rule_name           TEXT NOT NULL,
    source_ip           TEXT NOT NULL,
    username            TEXT NOT NULL DEFAULT '',
    severity            TEXT NOT NULL CHECK (severity IN ('Critical', 'High', 'Medium', 'Low')),
    description         TEXT NOT NULL,
    impact              TEXT NOT NULL DEFAULT '',
    recommended_action  TEXT NOT NULL DEFAULT '',
    mitre_id            TEXT NOT NULL DEFAULT '',
    mitre_name          TEXT NOT NULL DEFAULT '',
    event_count         INTEGER NOT NULL DEFAULT 0,
    first_seen          TEXT NOT NULL DEFAULT '',
    last_seen           TEXT NOT NULL DEFAULT '',
    evidence_json       TEXT NOT NULL DEFAULT '[]',
    dedupe_key          TEXT NOT NULL UNIQUE,
    created_at          TEXT NOT NULL
);

-- Investigation state is kept apart from the original evidence stored on the alert.
CREATE TABLE IF NOT EXISTS incidents (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    alert_id    INTEGER NOT NULL UNIQUE REFERENCES alerts(id) ON DELETE CASCADE,
    status      TEXT NOT NULL DEFAULT 'New'
                CHECK (status IN ('New', 'Investigating', 'Escalated', 'Resolved', 'False Positive')),
    assigned_to TEXT NOT NULL DEFAULT '',
    notes       TEXT NOT NULL DEFAULT '',
    updated_at  TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(severity);
CREATE INDEX IF NOT EXISTS idx_alerts_ip ON alerts(source_ip);
CREATE INDEX IF NOT EXISTS idx_events_ip ON event_logs(source_ip);
