from datetime import datetime, timedelta

from detection.detection_rules import (RULE_COMBINATION, RULE_INVALID, RULE_REPEATED,
                                         RULE_SUCCESS_AFTER, detect_repeated_failures,
                                         detect_success_after_failures, run_all)

T0 = datetime(2026, 10, 9, 10, 0, 0)


def ev(minutes, etype="login_failed", user="test_user", ip="192.0.2.10"):
    return {"timestamp": (T0 + timedelta(minutes=minutes)).isoformat(), "event_type": etype,
            "username": user, "source_ip": ip,
            "status": "failure" if etype == "login_failed" else "success"}


def test_five_failures_in_five_minutes_is_flagged():
    alerts = detect_repeated_failures([ev(m) for m in range(5)])
    assert len(alerts) == 1
    assert alerts[0]["severity"] == "High"
    assert alerts[0]["event_count"] == 5
    assert alerts[0]["mitre_id"] == "T1110"


def test_four_failures_not_flagged():
    assert detect_repeated_failures([ev(m) for m in range(4)]) == []


def test_failures_spread_out_not_flagged():
    assert detect_repeated_failures([ev(m * 30) for m in range(6)]) == []


def test_long_burst_creates_single_alert():
    alerts = detect_repeated_failures([ev(m * 0.5) for m in range(20)])
    assert len(alerts) == 1
    assert alerts[0]["event_count"] == 20


def test_different_ips_are_not_combined():
    events = [ev(m, ip=f"192.0.2.{m + 1}") for m in range(5)]
    assert detect_repeated_failures(events) == []


def test_many_usernames_maps_to_password_spraying():
    events = [ev(m, user=f"user{m}") for m in range(5)]
    alerts = detect_repeated_failures(events)
    assert alerts[0]["mitre_id"] == "T1110.003"
    assert "possible password spraying" in alerts[0]["description"]


def test_success_after_three_failures_is_medium():
    events = [ev(0), ev(1), ev(2), ev(3, "login_success")]
    alerts = detect_success_after_failures(events)
    assert len(alerts) == 1
    assert alerts[0]["severity"] == "Medium"


def test_success_after_five_failures_is_high():
    events = [ev(m) for m in range(5)] + [ev(5, "login_success")]
    assert detect_success_after_failures(events)[0]["severity"] == "High"


def test_normal_activity_produces_no_alerts():
    events = [ev(0, "login_success"), ev(30, "login_success", user="other", ip="10.0.0.5"),
              ev(60, "login_failed"), ev(61, "login_success")]
    assert run_all(events) == []


def test_success_for_different_account_is_not_correlated():
    events = [ev(0), ev(1), ev(2), ev(3, "login_success", user="someone_else")]
    assert detect_success_after_failures(events) == []


def test_combination_is_critical():
    events = [ev(m) for m in range(6)] + [ev(6, "login_success")]
    rules = {a["rule_name"]: a for a in run_all(events)}
    assert {RULE_REPEATED, RULE_SUCCESS_AFTER, RULE_COMBINATION} <= set(rules)
    assert rules[RULE_COMBINATION]["severity"] == "Critical"


def test_invalid_records_raise_low_data_quality_alert():
    alerts = run_all([], [{"record": {}, "errors": ["missing field: username"]}])
    assert alerts[0]["rule_name"] == RULE_INVALID
    assert alerts[0]["severity"] == "Low"
