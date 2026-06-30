"""
Postgres connection shim that mimics the subset of the sqlite3 API this app
relies on, so the rest of app.py barely has to change:
  - conn.execute(sql_with_question_marks, params)
  - conn.cursor() -> cursor with .execute()/.fetchone()/.fetchall()
  - rows behave like dicts: row["col"]
  - conn.commit() / conn.close()
  - `with conn:` wraps a transaction (commits on success, rolls back on error)
  - IntegrityError is exposed for uniqueness-violation handling
"""
import os
import re
import psycopg2
import psycopg2.extras
from psycopg2 import errors as pg_errors

IntegrityError = psycopg2.IntegrityError

_QMARK_RE = re.compile(r"\?")


def _translate(sql: str) -> str:
    """Convert sqlite-style '?' placeholders to psycopg2-style '%s'."""
    return _QMARK_RE.sub("%s", sql)


class _CursorWrapper:
    def __init__(self, real_cursor):
        self._c = real_cursor

    def execute(self, sql, params=None):
        self._c.execute(_translate(sql), params or None)
        return self

    def fetchone(self):
        return self._c.fetchone()

    def fetchall(self):
        return self._c.fetchall()

    def __getattr__(self, name):
        return getattr(self._c, name)


class _ConnWrapper:
    def __init__(self, real_conn):
        self._conn = real_conn

    def cursor(self):
        return _CursorWrapper(
            self._conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        )

    def execute(self, sql, params=None):
        cur = self.cursor()
        cur.execute(sql, params)
        return cur

    def commit(self):
        self._conn.commit()

    def rollback(self):
        self._conn.rollback()

    def close(self):
        # Discard any uncommitted work rather than leaving it hanging.
        try:
            self._conn.rollback()
        except Exception:
            pass
        self._conn.close()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        if exc_type is None:
            self._conn.commit()
        else:
            self._conn.rollback()
        return False


def get_pg_connection():
    dsn = os.environ.get("DATABASE_URL", "")
    if not dsn:
        raise RuntimeError("DATABASE_URL environment variable must be set (Postgres connection string).")
    # Railway/Heroku-style URLs sometimes use postgres:// — psycopg2 accepts both,
    # but normalize anyway for safety.
    if dsn.startswith("postgres://"):
        dsn = "postgresql://" + dsn[len("postgres://"):]
    raw = psycopg2.connect(dsn, sslmode=os.environ.get("PGSSLMODE", "require"))
    return _ConnWrapper(raw)