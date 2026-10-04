"""SQLite persistence: connection management, schema and transactions."""

from __future__ import annotations

import os
import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager

# The database path is resolved lazily so tests can override it before the
# first connection is opened.
DB_PATH: str = os.environ.get("SUBNET_DB_PATH", "/data/subnets.db")

# SQLite returns SQLITE_BUSY immediately when another connection holds the
# write lock; wait this long before giving up.
BUSY_TIMEOUT_SECONDS = 10.0


def _connect() -> sqlite3.Connection:
    directory = os.path.dirname(os.path.abspath(DB_PATH))
    os.makedirs(directory, exist_ok=True)
    conn = sqlite3.connect(
        DB_PATH,
        timeout=BUSY_TIMEOUT_SECONDS,
        isolation_level=None,  # autocommit; transactions are managed explicitly
        check_same_thread=False,
    )
    conn.row_factory = sqlite3.Row
    conn.execute(f"PRAGMA busy_timeout = {int(BUSY_TIMEOUT_SECONDS * 1000)}")
    conn.execute("PRAGMA foreign_keys = ON")
    # WAL lets readers run while a writer holds the lock; allocation itself
    # is still serialised by the BEGIN IMMEDIATE write transaction.
    conn.execute("PRAGMA journal_mode = WAL")
    conn.execute("PRAGMA synchronous = FULL")
    return conn


def init_db() -> None:
    with get_conn() as conn:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS pools (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                cidr        TEXT    NOT NULL UNIQUE,
                created_at  TEXT    NOT NULL
            );

            CREATE TABLE IF NOT EXISTS exclusions (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                pool_id     INTEGER NOT NULL REFERENCES pools(id) ON DELETE CASCADE,
                cidr        TEXT    NOT NULL,
                created_at  TEXT    NOT NULL,
                UNIQUE (pool_id, cidr)
            );

            CREATE TABLE IF NOT EXISTS allocations (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                pool_id         INTEGER NOT NULL REFERENCES pools(id) ON DELETE CASCADE,
                cidr            TEXT    NOT NULL,
                request_id      TEXT    NOT NULL UNIQUE,
                prefix_length   INTEGER NOT NULL,
                created_at      TEXT    NOT NULL
            );

            -- One row per completed restore; the primary key makes a repeated
            -- restore_id replay the original result instead of restoring twice.
            CREATE TABLE IF NOT EXISTS snapshot_restores (
                restore_id  TEXT    PRIMARY KEY,
                pool_id     INTEGER NOT NULL REFERENCES pools(id) ON DELETE CASCADE,
                digest      TEXT    NOT NULL,
                created_at  TEXT    NOT NULL
            );

            -- One row per completed pool partition.  The UNIQUE operation_id
            -- makes a retried partition replay the original result instead of
            -- splitting twice.  source_pool_id is a plain historical reference:
            -- the migration itself deletes the source pool row, so no FK.
            CREATE TABLE IF NOT EXISTS pool_migrations (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                operation_id    TEXT    NOT NULL UNIQUE,
                source_pool_id  INTEGER NOT NULL,
                source_cidr     TEXT    NOT NULL,
                sub_pools       TEXT    NOT NULL,
                created_at      TEXT    NOT NULL
            );

            -- Confirmable BGP announcement plans.  Every row is immutable
            -- after creation: only ``status`` moves 'planned' -> 'active'
            -- once, after the pinned pool state digest is re-verified.
            -- Deleting the pool cascades to its plans.
            CREATE TABLE IF NOT EXISTS bgp_plans (
                plan_id          TEXT    PRIMARY KEY,
                pool_id          INTEGER NOT NULL REFERENCES pools(id) ON DELETE CASCADE,
                params           TEXT    NOT NULL,
                audit_results    TEXT    NOT NULL,
                pool_state       TEXT    NOT NULL,
                state_digest     TEXT    NOT NULL,
                status           TEXT    NOT NULL CHECK (status IN ('planned', 'active')),
                created_at       TEXT    NOT NULL,
                activated_at     TEXT
            );

            -- One row per completed policy-gated batch reservation.  The
            -- batch_id primary key makes a retried batch replay the original
            -- result instead of reserving twice; params is the canonical
            -- request fingerprint used to detect conflicting reuses.
            CREATE TABLE IF NOT EXISTS reservation_batches (
                batch_id    TEXT    PRIMARY KEY,
                pool_id     INTEGER NOT NULL REFERENCES pools(id) ON DELETE CASCADE,
                params      TEXT    NOT NULL,
                result      TEXT    NOT NULL,
                created_at  TEXT    NOT NULL
            );

            -- Fast lookup of all plans belonging to one pool.
            CREATE INDEX IF NOT EXISTS idx_allocations_pool
                ON allocations(pool_id);
            CREATE INDEX IF NOT EXISTS idx_exclusions_pool
                ON exclusions(pool_id);
            CREATE INDEX IF NOT EXISTS idx_bgp_plans_pool
                ON bgp_plans(pool_id);
            """
        )


@contextmanager
def get_conn() -> Iterator[sqlite3.Connection]:
    conn = _connect()
    try:
        yield conn
    finally:
        conn.close()


@contextmanager
def write_transaction() -> Iterator[sqlite3.Connection]:
    """Open an immediate write transaction.

    ``BEGIN IMMEDIATE`` acquires the reserved write lock up-front, so two
    concurrent allocations are serialised: the second one waits (up to
    ``busy_timeout``) instead of failing on commit.
    """

    conn = _connect()
    try:
        conn.execute("BEGIN IMMEDIATE")
        yield conn
        conn.execute("COMMIT")
    except Exception:
        conn.execute("ROLLBACK")
        raise
    finally:
        conn.close()


@contextmanager
def read_transaction() -> Iterator[sqlite3.Connection]:
    """Open a deferred (read) transaction for a consistent snapshot."""

    conn = _connect()
    try:
        conn.execute("BEGIN")
        yield conn
        conn.execute("COMMIT")
    except Exception:
        conn.execute("ROLLBACK")
        raise
    finally:
        conn.close()
