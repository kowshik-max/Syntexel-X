import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "syntexel.db")
LOG_PATH = os.path.join(BASE_DIR, "data", "sample_auth_logs.json")

# Lab-defined thresholds (starting values, not universal security standards)
FAILURE_THRESHOLD = 5
FAILURE_WINDOW_MINUTES = 5
SUCCESS_AFTER_FAILURE_MIN = 3

STATUSES = ["New", "Investigating", "Escalated", "Resolved", "False Positive"]
