"""Validate raw authentication log records before they reach the detection engine."""
import ipaddress
import json
from datetime import datetime

REQUIRED_FIELDS = ("timestamp", "event_type", "username", "source_ip", "status")
VALID_EVENT_TYPES = {"login_failed", "login_success", "logout", "password_reset"}
VALID_STATUSES = {"success", "failure"}


def parse_ts(value):
    """Parse an ISO-8601 timestamp. Raises ValueError if malformed."""
    if not isinstance(value, str):
        raise ValueError("timestamp must be a string")
    return datetime.fromisoformat(value)


def validate_event(event):
    """Return a list of problems with one record (empty list = valid)."""
    if not isinstance(event, dict):
        return ["record is not a JSON object"]

    errors = []
    for field in REQUIRED_FIELDS:
        value = event.get(field)
        if value is None or (isinstance(value, str) and not value.strip()):
            errors.append(f"missing field: {field}")

    if event.get("timestamp"):
        try:
            parse_ts(event["timestamp"])
        except (ValueError, TypeError):
            errors.append("malformed timestamp")

    if event.get("event_type") and event["event_type"] not in VALID_EVENT_TYPES:
        errors.append(f"unknown event_type: {event['event_type']!r}")

    if event.get("status") and event["status"] not in VALID_STATUSES:
        errors.append(f"unknown status: {event['status']!r}")

    if event.get("source_ip"):
        try:
            ipaddress.ip_address(str(event["source_ip"]))
        except ValueError:
            errors.append("malformed source_ip")

    return errors


def parse_events(raw_events):
    """Split raw records into (valid_events, invalid_records).

    invalid_records items look like {"record": <original>, "errors": [...]}.
    """
    valid, invalid = [], []
    for record in raw_events:
        errors = validate_event(record)
        if errors:
            invalid.append({"record": record, "errors": errors})
        else:
            valid.append({field: str(record[field]).strip() for field in REQUIRED_FIELDS})
    return valid, invalid


def load_log_file(path):
    """Read a JSON log file containing a list of event objects."""
    with open(path, "r", encoding="utf-8") as handle:
        data = json.load(handle)
    if not isinstance(data, list):
        raise ValueError("log file must contain a JSON list of events")
    return data
