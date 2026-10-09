"""Rule-based detection engine.

Every rule is simple and explainable: no trained model is involved. Rules return alert
dicts that carry their own evidence so an analyst can verify them.
"""
from collections import defaultdict
from datetime import timedelta

import config
from detection import mitre_mapping as mitre
from detection import severity as sev
from detection.log_parser import parse_ts

RULE_REPEATED = "Repeated Failed Logins"
RULE_SUCCESS_AFTER = "Success After Repeated Failures"
RULE_COMBINATION = "Suspicious Event Combination"
RULE_INVALID = "Invalid Log Record"


def _alert(rule, severity, ip, username, description, impact, action, evidence, techniques):
    times = sorted(e["timestamp"] for e in evidence) if evidence and "timestamp" in evidence[0] else []
    ids, names = mitre.summarize(techniques)
    return {
        "rule_name": rule,
        "severity": severity,
        "source_ip": ip,
        "username": username,
        "description": description,
        "impact": impact,
        "recommended_action": action,
        "event_count": len(evidence),
        "first_seen": times[0] if times else "",
        "last_seen": times[-1] if times else "",
        "evidence": evidence,
        "mitre_id": ids,
        "mitre_name": names,
    }


def detect_repeated_failures(events, threshold=None, window_minutes=None):
    """>= threshold failed logins from one IP inside the window -> one alert per burst."""
    threshold = threshold or config.FAILURE_THRESHOLD
    window = timedelta(minutes=window_minutes or config.FAILURE_WINDOW_MINUTES)

    by_ip = defaultdict(list)
    for event in events:
        if event.get("event_type") == "login_failed":
            by_ip[event["source_ip"]].append((parse_ts(event["timestamp"]), event))

    alerts = []
    for ip, records in by_ip.items():
        records.sort(key=lambda r: r[0])
        n, i = len(records), 0
        while i < n:
            j = i
            while j + 1 < n and records[j + 1][0] - records[i][0] <= window:
                j += 1
            if j - i + 1 >= threshold:
                # extend the burst while failures keep arriving, so one burst = one alert
                k = j
                while k + 1 < n and records[k + 1][0] - records[k][0] <= window:
                    k += 1
                cluster = [r[1] for r in records[i:k + 1]]
                users = sorted({e["username"] for e in cluster})
                spray = len(users) >= 3
                desc = (
                    f"{len(cluster)} failed logins from {ip} against {len(users)} account(s) "
                    f"({', '.join(users[:5])}{'...' if len(users) > 5 else ''}) within "
                    f"{window.seconds // 60} minutes of each other. "
                    + ("Pattern is consistent with possible password spraying. " if spray
                       else "Pattern is consistent with a possible brute-force attempt. ")
                    + "This is an indicator, not proof of compromise."
                )
                alerts.append(_alert(
                    RULE_REPEATED,
                    sev.severity_repeated_failures(len(cluster), len(users)),
                    ip, ", ".join(users), desc,
                    "If malicious, the attacker may gain unauthorized access to the targeted account(s).",
                    "Validate whether the source IP is expected; review authentication logs for the "
                    "targeted accounts; apply rate limiting/lockout or block the IP if confirmed malicious; "
                    "follow the escalation procedure.",
                    cluster, mitre.map_repeated_failures(len(users)),
                ))
                i = k + 1
            else:
                i += 1
    return alerts


def detect_success_after_failures(events, min_failures=None, window_minutes=None):
    """A successful login preceded by several failures for the same account and IP."""
    min_failures = min_failures or config.SUCCESS_AFTER_FAILURE_MIN
    window = timedelta(minutes=window_minutes or config.FAILURE_WINDOW_MINUTES)

    failures = defaultdict(list)
    for event in events:
        if event.get("event_type") == "login_failed":
            failures[(event["username"], event["source_ip"])].append((parse_ts(event["timestamp"]), event))

    alerts = []
    for event in events:
        if event.get("event_type") != "login_success":
            continue
        t = parse_ts(event["timestamp"])
        key = (event["username"], event["source_ip"])
        prior = [e for (ft, e) in failures.get(key, []) if t - window <= ft <= t]
        if len(prior) >= min_failures:
            evidence = sorted(prior, key=lambda e: e["timestamp"]) + [event]
            alerts.append(_alert(
                RULE_SUCCESS_AFTER,
                sev.severity_success_after_failures(len(prior)),
                event["source_ip"], event["username"],
                f"Successful login for '{event['username']}' from {event['source_ip']} after "
                f"{len(prior)} failed attempts in the preceding {window.seconds // 60} minutes. "
                "Could be a user mistyping a password, or a guessed credential - needs investigation.",
                "If malicious, the account may already be accessed by an unauthorized party.",
                "Contact the account owner to confirm the login; review activity after the success; "
                "reset credentials and revoke sessions if the login is not legitimate.",
                evidence, mitre.map_success_after_failures(),
            ))
    return alerts


def detect_combination(repeated_alerts, success_alerts):
    """Same IP triggers both indicators -> a stronger, correlated finding."""
    success_by_ip = defaultdict(list)
    for a in success_alerts:
        success_by_ip[a["source_ip"]].append(a)

    alerts = []
    for rep in repeated_alerts:
        for suc in success_by_ip.get(rep["source_ip"], []):
            evidence = {(e["timestamp"], e["event_type"], e["username"], e["source_ip"]): e
                        for e in rep["evidence"] + suc["evidence"]}
            ordered = sorted(evidence.values(), key=lambda e: e["timestamp"])
            alerts.append(_alert(
                RULE_COMBINATION, sev.severity_combination(), rep["source_ip"], suc["username"],
                f"{rep['source_ip']} produced a burst of failed logins and then a successful login "
                f"for '{suc['username']}'. Two independent indicators together raise confidence "
                "that a credential may have been guessed. Still requires analyst confirmation.",
                "Possible unauthorized access to a valid account following credential guessing.",
                "Treat as priority: isolate or reset the account, revoke active sessions, block the source "
                "IP, review post-login activity, and escalate per procedure. Retest after remediation.",
                ordered, mitre.map_combination(),
            ))
    return alerts


def detect_invalid_records(invalid_records):
    """Data-quality alert so malformed logs are visible rather than silently dropped."""
    if not invalid_records:
        return []
    alert = _alert(
        RULE_INVALID, sev.severity_invalid_records(), "n/a", "n/a",
        f"{len(invalid_records)} log record(s) failed validation (missing fields, bad timestamp, "
        "unknown event type or malformed IP). Detection coverage may be reduced.",
        "Malformed logs can hide activity from detection rules.",
        "Check the log source and parser configuration; fix the logging pipeline.",
        invalid_records, mitre.map_none(),
    )
    return [alert]


def run_all(events, invalid_records=None):
    repeated = detect_repeated_failures(events)
    success = detect_success_after_failures(events)
    combo = detect_combination(repeated, success)
    invalid = detect_invalid_records(invalid_records or [])
    return repeated + success + combo + invalid
