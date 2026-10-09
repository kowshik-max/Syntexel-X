from detection.log_parser import parse_events, validate_event


def ev(**over):
    base = {"timestamp": "2026-10-09T10:00:00", "event_type": "login_failed",
            "username": "test_user", "source_ip": "192.0.2.10", "status": "failure"}
    base.update(over)
    return base


def test_valid_event_has_no_errors():
    assert validate_event(ev()) == []


def test_missing_field_is_reported():
    bad = ev()
    del bad["username"]
    assert any("username" in e for e in validate_event(bad))


def test_malformed_timestamp():
    assert "malformed timestamp" in validate_event(ev(timestamp="yesterday"))


def test_unknown_event_type():
    assert any("event_type" in e for e in validate_event(ev(event_type="teleport")))


def test_malformed_ip():
    assert "malformed source_ip" in validate_event(ev(source_ip="999.1.1.1"))


def test_non_dict_record():
    assert validate_event("oops") == ["record is not a JSON object"]


def test_parse_events_splits_valid_and_invalid():
    valid, invalid = parse_events([ev(), ev(timestamp="bad"), "junk"])
    assert len(valid) == 1
    assert len(invalid) == 2
    assert invalid[0]["errors"]
