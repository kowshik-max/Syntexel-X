import os
import sqlite3

import config

SCHEMA_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "schema.sql")


def get_conn(db_path=None):
    conn = sqlite3.connect(db_path or config.DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init_db(db_path=None):
    with open(SCHEMA_PATH, "r", encoding="utf-8") as handle:
        schema = handle.read()
    conn = get_conn(db_path)
    try:
        conn.executescript(schema)
        conn.commit()
    finally:
        conn.close()
