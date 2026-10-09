"""Severity assignment. Thresholds are lab-defined starting values, not industry standards."""

SEVERITY_ORDER = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1}


def severity_repeated_failures(failure_count, distinct_users=1):
    """Threshold already met when this is called; treated as High in this lab."""
    return "High"


def severity_success_after_failures(failure_count):
    """A success after several failures is more concerning the more failures preceded it."""
    return "High" if failure_count >= 5 else "Medium"


def severity_combination():
    """Independent indicators from the same source IP raise confidence in the finding."""
    return "Critical"


def severity_invalid_records():
    return "Low"
