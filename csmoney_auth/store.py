"""SQLite session store. Cookies, proxy URLs and Steam tokens are encrypted at rest with Fernet.

The key comes from the ``CSMONEY_STORE_KEY`` environment variable or from a key file that is created
on first use. Losing the key makes stored sessions unreadable (they are then simply re-obtained).
"""

import asyncio
import json
import logging
import os
import sqlite3
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from cryptography.fernet import Fernet, InvalidToken

from .core import CsMoneySession, SessionStatus, StorageError, StoredCookie

logger = logging.getLogger(__name__)

KEY_ENV = "CSMONEY_STORE_KEY"

_SCHEMA = """
CREATE TABLE IF NOT EXISTS sessions (
    account_id       TEXT PRIMARY KEY,
    steam_id         TEXT,
    csmoney_cookies  BLOB NOT NULL,  -- encrypted JSON list of cookies
    proxy            BLOB,           -- encrypted proxy URL (contains credentials)
    proxy_masked     TEXT,
    user_agent       TEXT NOT NULL,
    created_at       REAL NOT NULL,
    expires_at       REAL,
    status           TEXT NOT NULL,
    last_verified_at REAL,
    last_error       TEXT,
    updated_at       REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS steam_sessions (
    account_id TEXT PRIMARY KEY,
    steam_id   TEXT,
    data       BLOB NOT NULL,        -- encrypted aiosteampy SteamSession.serialize()
    updated_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS login_attempts (
    account_id           TEXT PRIMARY KEY,
    consecutive_failures INTEGER NOT NULL,
    last_attempt_at      REAL NOT NULL,
    last_error           TEXT,
    permanent            INTEGER NOT NULL DEFAULT 0,  -- a failure that retrying as-is cannot fix
    fingerprint          TEXT                         -- account credentials/proxy when blocked; a change clears it
);
"""

# columns added after the first release; ``CREATE TABLE IF NOT EXISTS`` never alters an existing table
_MIGRATIONS = {
    "login_attempts": {
        "permanent": "ALTER TABLE login_attempts ADD COLUMN permanent INTEGER NOT NULL DEFAULT 0",
        "fingerprint": "ALTER TABLE login_attempts ADD COLUMN fingerprint TEXT",
    },
}


def _migrate(conn: sqlite3.Connection) -> None:
    for table, columns in _MIGRATIONS.items():
        present = {row["name"] for row in conn.execute(f"PRAGMA table_info({table})")}
        for name, sql in columns.items():
            if name not in present:
                conn.execute(sql)


class SecretBox:
    def __init__(self, key: bytes):
        try:
            self._fernet = Fernet(key)
        except ValueError as e:
            raise StorageError(f"Invalid store key: {e}") from None

    @classmethod
    def load(cls, key_file: Path) -> "SecretBox":
        if env_key := os.environ.get(KEY_ENV):
            return cls(env_key.strip().encode())
        if key_file.exists():
            return cls(key_file.read_bytes().strip())
        key = Fernet.generate_key()
        key_file.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(key_file, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as f:
            f.write(key)
        logger.warning("Generated a new store key at %s - keep it private (or set %s instead)", key_file, KEY_ENV)
        return cls(key)

    def encrypt(self, obj: Any) -> bytes:
        return self._fernet.encrypt(json.dumps(obj, separators=(",", ":")).encode())

    def decrypt(self, blob: bytes) -> Any:
        try:
            return json.loads(self._fernet.decrypt(blob))
        except InvalidToken:
            raise StorageError("Cannot decrypt stored data - wrong store key?") from None


@dataclass(slots=True)
class LoginAttempts:
    consecutive_failures: int
    last_attempt_at: float
    last_error: str | None
    permanent: bool = False
    fingerprint: str | None = None


class SessionStore:
    def __init__(self, path: Path, box: SecretBox):
        self._path = path
        self._box = box
        self._conn: sqlite3.Connection | None = None
        self._lock = threading.Lock()

    async def open(self) -> "SessionStore":
        def _open() -> sqlite3.Connection:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            conn = sqlite3.connect(self._path, check_same_thread=False, isolation_level=None)
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA journal_mode=WAL")
            conn.executescript(_SCHEMA)
            _migrate(conn)
            return conn

        self._conn = await asyncio.to_thread(_open)
        return self

    async def close(self) -> None:
        if self._conn is not None:
            conn, self._conn = self._conn, None
            await asyncio.to_thread(conn.close)

    async def __aenter__(self) -> "SessionStore":
        return await self.open()

    async def __aexit__(self, *exc) -> None:
        await self.close()

    async def _run(self, sql: str, params: tuple = (), *, fetch: str | None = None) -> Any:
        if self._conn is None:
            raise StorageError("Store is not open")
        conn = self._conn

        def _exec() -> Any:
            with self._lock:
                cur = conn.execute(sql, params)
                if fetch == "one":
                    return cur.fetchone()
                if fetch == "all":
                    return cur.fetchall()
                return cur.rowcount

        return await asyncio.to_thread(_exec)

    # ── CS.MONEY sessions ─────────────────────────────────────────────────────

    def _row_to_session(self, row: sqlite3.Row) -> CsMoneySession:
        return CsMoneySession(
            account_id=row["account_id"],
            steam_id=row["steam_id"],
            cookies=[StoredCookie.from_dict(c) for c in self._box.decrypt(row["csmoney_cookies"])],
            proxy=self._box.decrypt(row["proxy"]) if row["proxy"] is not None else None,
            user_agent=row["user_agent"],
            created_at=row["created_at"],
            expires_at=row["expires_at"],
            status=SessionStatus(row["status"]),
            last_verified_at=row["last_verified_at"],
            last_error=row["last_error"],
        )

    async def get(self, account_id: str) -> CsMoneySession | None:
        row = await self._run("SELECT * FROM sessions WHERE account_id = ?", (account_id,), fetch="one")
        return self._row_to_session(row) if row else None

    async def list_sessions(self) -> list[CsMoneySession]:
        rows = await self._run("SELECT * FROM sessions ORDER BY account_id", fetch="all")
        return [self._row_to_session(r) for r in rows]

    async def list_overview(self) -> list[dict[str, Any]]:
        """Non-secret columns only (no decryption), for status output."""
        rows = await self._run(
            "SELECT account_id, steam_id, proxy_masked, user_agent, created_at, expires_at, status, "
            "last_verified_at, last_error FROM sessions ORDER BY account_id",
            fetch="all",
        )
        return [dict(r) for r in rows]

    async def save(self, s: CsMoneySession) -> None:
        proxy_masked = s.proxy_config.masked if s.proxy else None
        await self._run(
            """
            INSERT INTO sessions (account_id, steam_id, csmoney_cookies, proxy, proxy_masked, user_agent,
                                  created_at, expires_at, status, last_verified_at, last_error, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(account_id) DO UPDATE SET
                steam_id = excluded.steam_id, csmoney_cookies = excluded.csmoney_cookies,
                proxy = excluded.proxy, proxy_masked = excluded.proxy_masked, user_agent = excluded.user_agent,
                created_at = excluded.created_at, expires_at = excluded.expires_at, status = excluded.status,
                last_verified_at = excluded.last_verified_at, last_error = excluded.last_error,
                updated_at = excluded.updated_at
            """,
            (
                s.account_id,
                s.steam_id,
                self._box.encrypt([c.to_dict() for c in s.cookies]),
                self._box.encrypt(s.proxy) if s.proxy is not None else None,
                proxy_masked,
                s.user_agent,
                s.created_at,
                s.expires_at,
                s.status.value,
                s.last_verified_at,
                s.last_error,
                time.time(),
            ),
        )

    async def update_cookies(self, account_id: str, cookies: list[StoredCookie], expires_at: float | None) -> None:
        await self._run(
            "UPDATE sessions SET csmoney_cookies = ?, expires_at = ?, updated_at = ? WHERE account_id = ?",
            (self._box.encrypt([c.to_dict() for c in cookies]), expires_at, time.time(), account_id),
        )

    async def mark(
        self,
        account_id: str,
        status: SessionStatus,
        *,
        verified_at: float | None = None,
        error: str | None = None,
    ) -> None:
        """Update status. ``verified_at`` is written only when given; ``error`` is always overwritten."""
        await self._run(
            "UPDATE sessions SET status = ?, last_verified_at = COALESCE(?, last_verified_at), last_error = ?, "
            "updated_at = ? WHERE account_id = ?",
            (status.value, verified_at, error, time.time(), account_id),
        )

    async def delete(self, account_id: str) -> bool:
        deleted = await self._run("DELETE FROM sessions WHERE account_id = ?", (account_id,))
        await self._run("DELETE FROM steam_sessions WHERE account_id = ?", (account_id,))
        await self._run("DELETE FROM login_attempts WHERE account_id = ?", (account_id,))
        return bool(deleted)

    # ── Steam session state (aiosteampy) ──────────────────────────────────────

    async def get_steam_state(self, account_id: str) -> dict[str, Any] | None:
        row = await self._run("SELECT data FROM steam_sessions WHERE account_id = ?", (account_id,), fetch="one")
        return self._box.decrypt(row["data"]) if row else None

    async def save_steam_state(self, account_id: str, steam_id: str | None, state: dict[str, Any]) -> None:
        await self._run(
            "INSERT INTO steam_sessions (account_id, steam_id, data, updated_at) VALUES (?, ?, ?, ?) "
            "ON CONFLICT(account_id) DO UPDATE SET steam_id = excluded.steam_id, data = excluded.data, "
            "updated_at = excluded.updated_at",
            (account_id, steam_id, self._box.encrypt(state), time.time()),
        )

    async def delete_steam_state(self, account_id: str) -> None:
        await self._run("DELETE FROM steam_sessions WHERE account_id = ?", (account_id,))

    # ── browser login attempts (cooldown bookkeeping) ─────────────────────────

    async def get_login_attempts(self, account_id: str) -> LoginAttempts | None:
        row = await self._run(
            "SELECT consecutive_failures, last_attempt_at, last_error, permanent, fingerprint "
            "FROM login_attempts WHERE account_id = ?",
            (account_id,),
            fetch="one",
        )
        if row is None:
            return None
        return LoginAttempts(
            consecutive_failures=row["consecutive_failures"],
            last_attempt_at=row["last_attempt_at"],
            last_error=row["last_error"],
            permanent=bool(row["permanent"]),
            fingerprint=row["fingerprint"],
        )

    async def record_login_attempt(
        self,
        account_id: str,
        *,
        ok: bool,
        error: str | None = None,
        permanent: bool = False,
        fingerprint: str | None = None,
    ) -> None:
        """Record the outcome. A success clears the counter, the permanent flag and the fingerprint."""
        await self._run(
            """
            INSERT INTO login_attempts (account_id, consecutive_failures, last_attempt_at, last_error,
                                        permanent, fingerprint)
            VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(account_id) DO UPDATE SET
                consecutive_failures = CASE WHEN ? THEN 0 ELSE login_attempts.consecutive_failures + 1 END,
                last_attempt_at = excluded.last_attempt_at, last_error = excluded.last_error,
                permanent = excluded.permanent, fingerprint = excluded.fingerprint
            """,
            (account_id, 0 if ok else 1, time.time(), error, int(permanent and not ok), fingerprint, ok),
        )
