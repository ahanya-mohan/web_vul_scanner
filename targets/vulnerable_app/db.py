"""A tiny in-memory SQLite database for the practice target.

Shared across the dev server's threads by a single connection guarded with a
lock. Seeded with a handful of rows so the injectable routes return content.
"""

from __future__ import annotations

import sqlite3
import threading

_SCHEMA = """
CREATE TABLE products (id INTEGER PRIMARY KEY, name TEXT, price REAL);
CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, password TEXT);
"""

_SEED = """
INSERT INTO products (name, price) VALUES
    ('Phone', 499.0), ('Laptop', 1299.0), ('Headphones', 89.0), ('Charger', 19.0);
INSERT INTO users (username, password) VALUES
    ('alice', 'wonderland'), ('bob', 'builder');
"""


class Database:
    """A seeded in-memory SQLite database with a lock for thread safety."""

    def __init__(self) -> None:
        self._conn = sqlite3.connect(":memory:", check_same_thread=False)
        self._lock = threading.Lock()
        self._conn.executescript(_SCHEMA + _SEED)

    def execute(self, sql: str, params: tuple = ()) -> list[tuple]:
        with self._lock:
            return self._conn.execute(sql, params).fetchall()
