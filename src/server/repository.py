import json
import sqlite3
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from server.settings import DATABASE_URL
from utils.config import PROJECT_ROOT


def _sqlite_path() -> Path:
    if DATABASE_URL.startswith("sqlite:///"):
        path = Path(DATABASE_URL.replace("sqlite:///", "", 1))
        return path if path.is_absolute() else PROJECT_ROOT / path
    # The production plan uses PostgreSQL; this sqlite adapter keeps local
    # development and tests lightweight until the Postgres adapter is added.
    return PROJECT_ROOT / "trustmail_app.db"


class ScanRepository:
    def __init__(self) -> None:
        self.database_url = DATABASE_URL
        self.is_postgres = self.database_url.startswith(("postgres://", "postgresql://"))
        self.db_path = _sqlite_path()
        if not self.is_postgres:
            self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def _connect(self):
        if self.is_postgres:
            try:
                import psycopg
                from psycopg.rows import dict_row
            except ImportError as exc:
                raise RuntimeError("psycopg is required for PostgreSQL DATABASE_URL") from exc
            return psycopg.connect(self.database_url, row_factory=dict_row)
        return sqlite3.connect(self.db_path)

    @contextmanager
    def _db(self):
        conn = self._connect()
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def _init_db(self) -> None:
        try:
            with self._db() as conn:
                if self.is_postgres:
                    conn.execute(
                        """
                        CREATE TABLE IF NOT EXISTS scans (
                            id TEXT PRIMARY KEY,
                            user_id TEXT NOT NULL DEFAULT 'local',
                            subject TEXT NOT NULL,
                            sender TEXT NOT NULL,
                            final_label TEXT NOT NULL,
                            final_score DOUBLE PRECISION NOT NULL,
                            llm_used BOOLEAN NOT NULL,
                            degraded BOOLEAN NOT NULL,
                            evidence_json TEXT NOT NULL,
                            report_pdf TEXT,
                            report_json TEXT,
                            created_at TIMESTAMPTZ NOT NULL
                        )
                        """
                    )
                    conn.execute(
                        """
                        CREATE TABLE IF NOT EXISTS push_tokens (
                            token TEXT PRIMARY KEY,
                            user_id TEXT NOT NULL DEFAULT 'local',
                            platform TEXT NOT NULL,
                            created_at TIMESTAMPTZ NOT NULL
                        )
                        """
                    )
                    conn.execute(
                        """
                        CREATE TABLE IF NOT EXISTS gmail_tokens (
                            user_id TEXT PRIMARY KEY,
                            token_blob TEXT NOT NULL,
                            updated_at TIMESTAMPTZ NOT NULL
                        )
                        """
                    )
                    conn.execute(
                        """
                        CREATE TABLE IF NOT EXISTS password_reset_tokens (
                            token TEXT PRIMARY KEY,
                            user_id TEXT NOT NULL,
                            expires_at TIMESTAMPTZ NOT NULL,
                            created_at TIMESTAMPTZ NOT NULL
                        )
                        """
                    )
                else:
                    conn.execute(
                        """
                        CREATE TABLE IF NOT EXISTS scans (
                            id TEXT PRIMARY KEY,
                            user_id TEXT NOT NULL DEFAULT 'local',
                            subject TEXT NOT NULL,
                            sender TEXT NOT NULL,
                            final_label TEXT NOT NULL,
                            final_score REAL NOT NULL,
                            llm_used INTEGER NOT NULL,
                            degraded INTEGER NOT NULL,
                            evidence_json TEXT NOT NULL,
                            report_pdf TEXT,
                            report_json TEXT,
                            created_at TEXT NOT NULL
                        )
                        """
                    )
                    conn.execute(
                        """
                        CREATE TABLE IF NOT EXISTS push_tokens (
                            token TEXT PRIMARY KEY,
                            user_id TEXT NOT NULL DEFAULT 'local',
                            platform TEXT NOT NULL,
                            created_at TEXT NOT NULL
                        )
                        """
                    )
                    conn.execute(
                        """
                        CREATE TABLE IF NOT EXISTS gmail_tokens (
                            user_id TEXT PRIMARY KEY,
                            token_blob TEXT NOT NULL,
                            updated_at TEXT NOT NULL
                        )
                        """
                    )
                    conn.execute(
                        """
                        CREATE TABLE IF NOT EXISTS password_reset_tokens (
                            token TEXT PRIMARY KEY,
                            user_id TEXT NOT NULL,
                            expires_at TEXT NOT NULL,
                            created_at TEXT NOT NULL
                        )
                        """
                    )
                conn.execute("UPDATE scans SET final_label = 'queued' WHERE final_label = 'pending'")
                self._ensure_column(conn, "scans", "user_id", "TEXT NOT NULL DEFAULT 'local'")
                self._ensure_column(conn, "push_tokens", "user_id", "TEXT NOT NULL DEFAULT 'local'")
                conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS users (
                        id TEXT PRIMARY KEY,
                        email TEXT NOT NULL UNIQUE,
                        password_hash TEXT NOT NULL,
                        salt TEXT NOT NULL,
                        created_at TEXT NOT NULL
                    )
                    """
                )
                conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS scan_fingerprints (
                        scan_id        TEXT NOT NULL,
                        user_id        TEXT NOT NULL DEFAULT 'local',
                        fingerprint    TEXT NOT NULL,
                        sender_domain  TEXT NOT NULL DEFAULT '',
                        intent         TEXT NOT NULL DEFAULT 'unknown',
                        created_at     TEXT NOT NULL,
                        PRIMARY KEY (scan_id)
                    )
                    """
                )
                conn.execute(
                    "CREATE INDEX IF NOT EXISTS idx_sf_user_fp "
                    "ON scan_fingerprints (user_id, fingerprint, created_at)"
                )
                conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS rescan_events (
                        scan_id       TEXT NOT NULL PRIMARY KEY,
                        old_verdict   TEXT NOT NULL DEFAULT '',
                        new_verdict   TEXT NOT NULL DEFAULT '',
                        rescanned_at  TEXT NOT NULL
                    )
                    """
                )
        except Exception as e:
            print(f"[DB INIT] Concurrent initialization warning ignored: {e}")

    def _ensure_column(self, conn, table: str, column: str, definition: str) -> None:
        try:
            if self.is_postgres:
                conn.execute("SAVEPOINT ensure_col")
                try:
                    conn.execute(f"ALTER TABLE {table} ADD COLUMN IF NOT EXISTS {column} {definition}")
                    conn.execute("RELEASE SAVEPOINT ensure_col")
                except Exception:
                    conn.execute("ROLLBACK TO SAVEPOINT ensure_col")
                return

            existing = conn.execute(f"PRAGMA table_info({table})").fetchall()
            if any(row[1] == column for row in existing):
                return
            conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {definition}")
        except Exception:
            pass

    def create_queued_scan(
        self,
        *,
        subject: str,
        sender: str,
        evidence: dict[str, Any] | None = None,
        user_id: str = "local",
    ) -> str:
        return self.create_scan(
            user_id=user_id,
            subject=subject,
            sender=sender,
            final_label="queued",
            final_score=0.0,
            llm_used=False,
            degraded=False,
            evidence=evidence or {"status": "queued"},
            report_pdf=None,
            report_json=None,
        )

    def create_scan(
        self,
        *,
        subject: str,
        sender: str,
        final_label: str,
        final_score: float,
        llm_used: bool,
        degraded: bool,
        evidence: dict[str, Any],
        report_pdf: str | None,
        report_json: str | None,
        user_id: str = "local",
    ) -> str:
        scan_id = str(uuid.uuid4())
        created_at = datetime.now(timezone.utc).isoformat()
        placeholder = "%s" if self.is_postgres else "?"
        with self._db() as conn:
            conn.execute(
                f"""
                INSERT INTO scans (
                    id, user_id, subject, sender, final_label, final_score, llm_used,
                    degraded, evidence_json, report_pdf, report_json, created_at
                ) VALUES ({placeholder}, {placeholder}, {placeholder}, {placeholder}, {placeholder}, {placeholder}, {placeholder}, {placeholder}, {placeholder}, {placeholder}, {placeholder}, {placeholder})
                """,
                (
                    scan_id,
                    user_id,
                    subject,
                    sender,
                    final_label,
                    float(final_score),
                    llm_used if self.is_postgres else 1 if llm_used else 0,
                    degraded if self.is_postgres else 1 if degraded else 0,
                    json.dumps(evidence),
                    report_pdf,
                    report_json,
                    created_at,
                ),
            )
        return scan_id

    def complete_scan(
        self,
        scan_id: str,
        *,
        subject: str,
        sender: str,
        final_label: str,
        final_score: float,
        llm_used: bool,
        degraded: bool,
        evidence: dict[str, Any],
        report_pdf: str | None,
        report_json: str | None,
    ) -> None:
        placeholder = "%s" if self.is_postgres else "?"
        with self._db() as conn:
            conn.execute(
                f"""
                UPDATE scans
                SET subject = {placeholder}, sender = {placeholder}, final_label = {placeholder}, final_score = {placeholder},
                    llm_used = {placeholder}, degraded = {placeholder}, evidence_json = {placeholder},
                    report_pdf = {placeholder}, report_json = {placeholder}
                WHERE id = {placeholder}
                """,
                (
                    subject,
                    sender,
                    final_label,
                    float(final_score),
                    llm_used if self.is_postgres else 1 if llm_used else 0,
                    degraded if self.is_postgres else 1 if degraded else 0,
                    json.dumps(evidence),
                    report_pdf,
                    report_json,
                    scan_id,
                ),
            )

    def fail_scan(self, scan_id: str, error: str) -> None:
        scan = self.get_scan(scan_id)
        if scan is None:
            return
        evidence = scan.get("evidence") or {}
        evidence["status"] = "failed"
        evidence["error"] = error
        placeholder = "%s" if self.is_postgres else "?"
        with self._db() as conn:
            conn.execute(
                f"""
                UPDATE scans
                SET final_label = {placeholder}, degraded = {placeholder}, evidence_json = {placeholder}
                WHERE id = {placeholder}
                """,
                ("failed", True if self.is_postgres else 1, json.dumps(evidence), scan_id),
            )

    # Feature 6: Rescan support methods

    def update_scan_verdict(self, scan_id: str, new_verdict: str) -> None:
        """Update the final_label of an existing scan (used by rescan job)."""
        placeholder = "%s" if self.is_postgres else "?"
        try:
            with self._db() as conn:
                conn.execute(
                    f"UPDATE scans SET final_label = {placeholder} WHERE id = {placeholder}",
                    (new_verdict, scan_id),
                )
        except Exception as exc:
            import logging
            logging.getLogger("REPOSITORY").warning(
                "update_scan_verdict failed for %s: %s", scan_id, exc
            )

    def update_evidence(self, scan_id: str, evidence: dict) -> None:
        """Overwrite evidence_json for an existing scan."""
        placeholder = "%s" if self.is_postgres else "?"
        try:
            with self._db() as conn:
                conn.execute(
                    f"UPDATE scans SET evidence_json = {placeholder} WHERE id = {placeholder}",
                    (json.dumps(evidence), scan_id),
                )
        except Exception as exc:
            import logging
            logging.getLogger("REPOSITORY").warning(
                "update_evidence failed for %s: %s", scan_id, exc
            )

    def list_scans(self, user_id: str = "local") -> list[dict[str, Any]]:
        placeholder = "%s" if self.is_postgres else "?"
        with self._db() as conn:
            if not self.is_postgres:
                conn.row_factory = sqlite3.Row
            rows = conn.execute(
                f"SELECT * FROM scans WHERE user_id = {placeholder} ORDER BY created_at DESC",
                (user_id,),
            ).fetchall()
        return [self._row_to_summary(row) for row in rows]

    def get_scan(self, scan_id: str, user_id: str | None = None) -> dict[str, Any] | None:
        placeholder = "%s" if self.is_postgres else "?"
        with self._db() as conn:
            if not self.is_postgres:
                conn.row_factory = sqlite3.Row
            if user_id is None:
                row = conn.execute(f"SELECT * FROM scans WHERE id = {placeholder}", (scan_id,)).fetchone()
            else:
                row = conn.execute(
                    f"SELECT * FROM scans WHERE id = {placeholder} AND user_id = {placeholder}",
                    (scan_id, user_id),
                ).fetchone()
        if row is None:
            return None
        data = self._row_to_summary(row)
        data["evidence"] = json.loads(row["evidence_json"])
        data["report_pdf"] = row["report_pdf"]
        data["report_json"] = row["report_json"]
        return data

    def dashboard_counts(self, user_id: str = "local") -> dict[str, Any]:
        scans = self.list_scans(user_id=user_id)
        return {
            "total_scans": len(scans),
            "safe_count": sum(1 for s in scans if s["final_label"] == "legitimate"),
            "suspicious_count": sum(1 for s in scans if s["final_label"] == "suspicious"),
            "phishing_count": sum(1 for s in scans if s["final_label"] == "phishing"),
            "latest_scan": scans[0] if scans else None,
        }

    def ping(self) -> bool:
        try:
            with self._db() as conn:
                conn.execute("SELECT 1")
            return True
        except Exception:
            return False

    def upsert_push_token(self, token: str, platform: str, user_id: str = "local") -> None:
        created_at = datetime.now(timezone.utc).isoformat()
        placeholder = "%s" if self.is_postgres else "?"
        with self._db() as conn:
            if self.is_postgres:
                conn.execute(
                    """
                    INSERT INTO push_tokens (token, user_id, platform, created_at)
                    VALUES (%s, %s, %s, %s)
                    ON CONFLICT (token) DO UPDATE
                    SET user_id = EXCLUDED.user_id, platform = EXCLUDED.platform
                    """,
                    (token, user_id, platform, created_at),
                )
            else:
                conn.execute(
                    f"""
                    INSERT INTO push_tokens (token, user_id, platform, created_at)
                    VALUES ({placeholder}, {placeholder}, {placeholder}, {placeholder})
                    ON CONFLICT(token) DO UPDATE SET user_id = excluded.user_id, platform = excluded.platform
                    """,
                    (token, user_id, platform, created_at),
                )

    def list_push_tokens(self, user_id: str = "local") -> list[str]:
        placeholder = "%s" if self.is_postgres else "?"
        with self._db() as conn:
            rows = conn.execute(
                f"SELECT token FROM push_tokens WHERE user_id = {placeholder} ORDER BY created_at DESC",
                (user_id,),
            ).fetchall()
        return [row["token"] if isinstance(row, dict) else row[0] for row in rows]

    def create_user(self, *, email: str, password_hash: str, salt: str) -> str:
        user_id = str(uuid.uuid4())
        created_at = datetime.now(timezone.utc).isoformat()
        placeholder = "%s" if self.is_postgres else "?"
        with self._db() as conn:
            conn.execute(
                f"""
                INSERT INTO users (id, email, password_hash, salt, created_at)
                VALUES ({placeholder}, {placeholder}, {placeholder}, {placeholder}, {placeholder})
                """,
                (user_id, email.lower(), password_hash, salt, created_at),
            )
        return user_id

    def get_user_by_email(self, email: str) -> dict[str, Any] | None:
        placeholder = "%s" if self.is_postgres else "?"
        with self._db() as conn:
            if not self.is_postgres:
                conn.row_factory = sqlite3.Row
            row = conn.execute(
                f"SELECT * FROM users WHERE email = {placeholder}",
                (email.lower(),),
            ).fetchone()
        return dict(row) if row else None

    def get_user_by_id(self, user_id: str) -> dict[str, Any] | None:
        placeholder = "%s" if self.is_postgres else "?"
        with self._db() as conn:
            if not self.is_postgres:
                conn.row_factory = sqlite3.Row
            row = conn.execute(f"SELECT * FROM users WHERE id = {placeholder}", (user_id,)).fetchone()
        return dict(row) if row else None

    def store_gmail_token(self, user_id: str, token_blob: str) -> None:
        updated_at = datetime.now(timezone.utc).isoformat()
        placeholder = "%s" if self.is_postgres else "?"
        with self._db() as conn:
            if self.is_postgres:
                conn.execute(
                    """
                    INSERT INTO gmail_tokens (user_id, token_blob, updated_at)
                    VALUES (%s, %s, %s)
                    ON CONFLICT (user_id) DO UPDATE
                    SET token_blob = EXCLUDED.token_blob, updated_at = EXCLUDED.updated_at
                    """,
                    (user_id, token_blob, updated_at),
                )
            else:
                conn.execute(
                    f"""
                    INSERT INTO gmail_tokens (user_id, token_blob, updated_at)
                    VALUES ({placeholder}, {placeholder}, {placeholder})
                    ON CONFLICT(user_id) DO UPDATE
                    SET token_blob = excluded.token_blob, updated_at = excluded.updated_at
                    """,
                    (user_id, token_blob, updated_at),
                )

    def get_gmail_token(self, user_id: str) -> str | None:
        placeholder = "%s" if self.is_postgres else "?"
        with self._db() as conn:
            if not self.is_postgres:
                conn.row_factory = sqlite3.Row
            row = conn.execute(
                f"SELECT token_blob FROM gmail_tokens WHERE user_id = {placeholder}",
                (user_id,),
            ).fetchone()
        if not row:
            return None
        return row["token_blob"] if isinstance(row, dict) else row["token_blob"]

    def delete_gmail_token(self, user_id: str) -> None:
        placeholder = "%s" if self.is_postgres else "?"
        with self._db() as conn:
            conn.execute(
                f"DELETE FROM gmail_tokens WHERE user_id = {placeholder}",
                (user_id,),
            )

    def list_gmail_user_ids(self) -> list[str]:
        with self._db() as conn:
            rows = conn.execute("SELECT user_id FROM gmail_tokens ORDER BY updated_at DESC").fetchall()
        return [row["user_id"] if isinstance(row, dict) else row[0] for row in rows]

    def create_password_reset_token(self, token: str, user_id: str, expires_at: str) -> None:
        created_at = datetime.now(timezone.utc).isoformat()
        placeholder = "%s" if self.is_postgres else "?"
        with self._db() as conn:
            if self.is_postgres:
                conn.execute(
                    """
                    INSERT INTO password_reset_tokens (token, user_id, expires_at, created_at)
                    VALUES (%s, %s, %s, %s)
                    ON CONFLICT (token) DO UPDATE SET
                        user_id = EXCLUDED.user_id,
                        expires_at = EXCLUDED.expires_at,
                        created_at = EXCLUDED.created_at
                    """,
                    (token, user_id, expires_at, created_at),
                )
            else:
                conn.execute(
                    """
                    INSERT OR REPLACE INTO password_reset_tokens (token, user_id, expires_at, created_at)
                    VALUES (?, ?, ?, ?)
                    """,
                    (token, user_id, expires_at, created_at),
                )

    def get_password_reset_token(self, token: str) -> dict[str, Any] | None:
        placeholder = "%s" if self.is_postgres else "?"
        with self._db() as conn:
            if not self.is_postgres:
                conn.row_factory = sqlite3.Row
            row = conn.execute(
                f"SELECT * FROM password_reset_tokens WHERE token = {placeholder}",
                (token,),
            ).fetchone()
        return dict(row) if row else None

    def delete_password_reset_token(self, token: str) -> None:
        placeholder = "%s" if self.is_postgres else "?"
        with self._db() as conn:
            conn.execute(
                f"DELETE FROM password_reset_tokens WHERE token = {placeholder}",
                (token,),
            )

    def update_user_password(self, user_id: str, password_hash: str, salt: str) -> None:
        placeholder = "%s" if self.is_postgres else "?"
        with self._db() as conn:
            conn.execute(
                f"""
                UPDATE users
                SET password_hash = {placeholder}, salt = {placeholder}
                WHERE id = {placeholder}
                """,
                (password_hash, salt, user_id),
            )

    @staticmethod
    def _row_to_summary(row) -> dict[str, Any]:
        created_at = row["created_at"]
        if hasattr(created_at, "isoformat"):
            created_at = created_at.isoformat()
        return {
            "id": row["id"],
            "user_id": row["user_id"],
            "subject": row["subject"],
            "sender": row["sender"],
            "final_label": row["final_label"],
            "final_score": row["final_score"],
            "llm_used": bool(row["llm_used"]),
            "degraded": bool(row["degraded"]),
            "report_pdf": row["report_pdf"],
            "report_json": row["report_json"],
            "created_at": created_at,
        }


    def store_otp(self, email: str, otp: str, expires_at: str) -> None:
        created_at = datetime.now(timezone.utc).isoformat()
        placeholder = "%s" if self.is_postgres else "?"
        with self._db() as conn:
            conn.execute(
                f"CREATE TABLE IF NOT EXISTS otp_tokens (email TEXT PRIMARY KEY, otp TEXT NOT NULL, expires_at TEXT NOT NULL, created_at TEXT NOT NULL)"
            )
            if self.is_postgres:
                conn.execute(
                    f"INSERT INTO otp_tokens (email, otp, expires_at, created_at) VALUES ({placeholder}, {placeholder}, {placeholder}, {placeholder}) ON CONFLICT (email) DO UPDATE SET otp = EXCLUDED.otp, expires_at = EXCLUDED.expires_at",
                    (email, otp, expires_at, created_at)
                )
            else:
                conn.execute(
                    f"INSERT INTO otp_tokens (email, otp, expires_at, created_at) VALUES ({placeholder}, {placeholder}, {placeholder}, {placeholder}) ON CONFLICT(email) DO UPDATE SET otp = excluded.otp, expires_at = excluded.expires_at",
                    (email, otp, expires_at, created_at)
                )

    def get_otp(self, email: str) -> dict | None:
        placeholder = "%s" if self.is_postgres else "?"
        with self._db() as conn:
            try:
                if not self.is_postgres:
                    conn.row_factory = sqlite3.Row
                row = conn.execute(f"SELECT * FROM otp_tokens WHERE email = {placeholder}", (email,)).fetchone()
                if not row:
                    return None
                return dict(row)
            except Exception:
                return None

    def delete_otp(self, email: str) -> None:
        placeholder = "%s" if self.is_postgres else "?"
        with self._db() as conn:
            try:
                conn.execute(f"DELETE FROM otp_tokens WHERE email = {placeholder}", (email,))
            except Exception:
                pass

    def store_backup_token(self, user_id: str, email: str, name: str, token_blob: str) -> None:
        updated_at = datetime.now(timezone.utc).isoformat()
        placeholder = "%s" if self.is_postgres else "?"
        with self._db() as conn:
            conn.execute(
                f"CREATE TABLE IF NOT EXISTS google_backup_tokens (user_id TEXT PRIMARY KEY, email TEXT NOT NULL, name TEXT NOT NULL, token_blob TEXT NOT NULL, updated_at TEXT NOT NULL)"
            )
            if self.is_postgres:
                conn.execute(
                    f"INSERT INTO google_backup_tokens (user_id, email, name, token_blob, updated_at) VALUES ({placeholder}, {placeholder}, {placeholder}, {placeholder}, {placeholder}) ON CONFLICT (user_id) DO UPDATE SET token_blob = EXCLUDED.token_blob, email = EXCLUDED.email, name = EXCLUDED.name, updated_at = EXCLUDED.updated_at",
                    (user_id, email, name, token_blob, updated_at)
                )
            else:
                conn.execute(
                    f"INSERT INTO google_backup_tokens (user_id, email, name, token_blob, updated_at) VALUES ({placeholder}, {placeholder}, {placeholder}, {placeholder}, {placeholder}) ON CONFLICT(user_id) DO UPDATE SET token_blob = excluded.token_blob, email = excluded.email, name = excluded.name, updated_at = excluded.updated_at",
                    (user_id, email, name, token_blob, updated_at)
                )

    def get_backup_token(self, user_id: str) -> str | None:
        placeholder = "%s" if self.is_postgres else "?"
        with self._db() as conn:
            try:
                row = conn.execute(f"SELECT token_blob FROM google_backup_tokens WHERE user_id = {placeholder}", (user_id,)).fetchone()
                if not row:
                    return None
                return row["token_blob"] if isinstance(row, dict) else row[0]
            except Exception:
                return None

    def delete_backup_token(self, user_id: str) -> None:
        placeholder = "%s" if self.is_postgres else "?"
        with self._db() as conn:
            try:
                conn.execute(f"DELETE FROM google_backup_tokens WHERE user_id = {placeholder}", (user_id,))
            except Exception:
                pass

    def upsert_notification_preferences(self, user_id: str, critical_alerts: bool, weekly_summary: bool) -> None:
        updated_at = datetime.now(timezone.utc).isoformat()
        placeholder = "%s" if self.is_postgres else "?"
        with self._db() as conn:
            if self.is_postgres:
                conn.execute(
                    "CREATE TABLE IF NOT EXISTS notification_preferences (user_id TEXT PRIMARY KEY, critical_alerts BOOLEAN NOT NULL, weekly_summary BOOLEAN NOT NULL, updated_at TEXT NOT NULL)"
                )
                conn.execute(
                    f"INSERT INTO notification_preferences (user_id, critical_alerts, weekly_summary, updated_at) VALUES ({placeholder}, {placeholder}, {placeholder}, {placeholder}) ON CONFLICT (user_id) DO UPDATE SET critical_alerts = EXCLUDED.critical_alerts, weekly_summary = EXCLUDED.weekly_summary, updated_at = EXCLUDED.updated_at",
                    (user_id, critical_alerts, weekly_summary, updated_at)
                )
            else:
                critical_int = 1 if critical_alerts else 0
                weekly_int = 1 if weekly_summary else 0
                conn.execute(
                    "CREATE TABLE IF NOT EXISTS notification_preferences (user_id TEXT PRIMARY KEY, critical_alerts INTEGER NOT NULL, weekly_summary INTEGER NOT NULL, updated_at TEXT NOT NULL)"
                )
                conn.execute(
                    f"INSERT INTO notification_preferences (user_id, critical_alerts, weekly_summary, updated_at) VALUES ({placeholder}, {placeholder}, {placeholder}, {placeholder}) ON CONFLICT(user_id) DO UPDATE SET critical_alerts = excluded.critical_alerts, weekly_summary = excluded.weekly_summary, updated_at = excluded.updated_at",
                    (user_id, critical_int, weekly_int, updated_at)
                )

    def get_notification_preferences(self, user_id: str) -> dict | None:
        placeholder = "%s" if self.is_postgres else "?"
        with self._db() as conn:
            try:
                if not self.is_postgres:
                    conn.row_factory = sqlite3.Row
                row = conn.execute(f"SELECT * FROM notification_preferences WHERE user_id = {placeholder}", (user_id,)).fetchone()
                if not row:
                    return None
                d = dict(row)
                d['critical_alerts'] = bool(d.get('critical_alerts', 1))
                d['weekly_summary'] = bool(d.get('weekly_summary', 1))
                return d
            except Exception:
                return None

    def store_google_contacts_token(self, user_id: str, token_blob: str) -> None:
        updated_at = datetime.now(timezone.utc).isoformat()
        placeholder = "%s" if self.is_postgres else "?"
        with self._db() as conn:
            conn.execute(
                f"CREATE TABLE IF NOT EXISTS google_contacts_tokens (user_id TEXT PRIMARY KEY, token_blob TEXT NOT NULL, updated_at TEXT NOT NULL)"
            )
            if self.is_postgres:
                conn.execute(
                    f"INSERT INTO google_contacts_tokens (user_id, token_blob, updated_at) VALUES ({placeholder}, {placeholder}, {placeholder}) ON CONFLICT (user_id) DO UPDATE SET token_blob = EXCLUDED.token_blob, updated_at = EXCLUDED.updated_at",
                    (user_id, token_blob, updated_at)
                )
            else:
                conn.execute(
                    f"INSERT INTO google_contacts_tokens (user_id, token_blob, updated_at) VALUES ({placeholder}, {placeholder}, {placeholder}) ON CONFLICT(user_id) DO UPDATE SET token_blob = excluded.token_blob, updated_at = excluded.updated_at",
                    (user_id, token_blob, updated_at)
                )

    def get_google_contacts_token(self, user_id: str) -> str | None:
        placeholder = "%s" if self.is_postgres else "?"
        with self._db() as conn:
            try:
                row = conn.execute(f"SELECT token_blob FROM google_contacts_tokens WHERE user_id = {placeholder}", (user_id,)).fetchone()
                if not row:
                    return None
                return row["token_blob"] if isinstance(row, dict) else row[0]
            except Exception:
                return None
                
    def delete_google_contacts_token(self, user_id: str) -> None:
        placeholder = "%s" if self.is_postgres else "?"
        with self._db() as conn:
            try:
                conn.execute(f"DELETE FROM google_contacts_tokens WHERE user_id = {placeholder}", (user_id,))
            except Exception:
                pass

    def save_trust_rules(self, user_id: str, auto_trust_contacts: bool, whitelist: list[str], blacklist: list[str]) -> None:
        updated_at = datetime.now(timezone.utc).isoformat()
        placeholder = "%s" if self.is_postgres else "?"
        auto_trust = 1 if auto_trust_contacts else 0
        import json
        with self._db() as conn:
            conn.execute(
                f"CREATE TABLE IF NOT EXISTS trust_rules (user_id TEXT PRIMARY KEY, auto_trust_contacts INTEGER NOT NULL, whitelist TEXT NOT NULL, blacklist TEXT NOT NULL, updated_at TEXT NOT NULL)"
            )
            if self.is_postgres:
                conn.execute(
                    f"INSERT INTO trust_rules (user_id, auto_trust_contacts, whitelist, blacklist, updated_at) VALUES ({placeholder}, {placeholder}, {placeholder}, {placeholder}, {placeholder}) ON CONFLICT (user_id) DO UPDATE SET auto_trust_contacts = EXCLUDED.auto_trust_contacts, whitelist = EXCLUDED.whitelist, blacklist = EXCLUDED.blacklist, updated_at = EXCLUDED.updated_at",
                    (user_id, auto_trust, json.dumps(whitelist), json.dumps(blacklist), updated_at)
                )
            else:
                conn.execute(
                    f"INSERT INTO trust_rules (user_id, auto_trust_contacts, whitelist, blacklist, updated_at) VALUES ({placeholder}, {placeholder}, {placeholder}, {placeholder}, {placeholder}) ON CONFLICT(user_id) DO UPDATE SET auto_trust_contacts = excluded.auto_trust_contacts, whitelist = excluded.whitelist, blacklist = excluded.blacklist, updated_at = excluded.updated_at",
                    (user_id, auto_trust, json.dumps(whitelist), json.dumps(blacklist), updated_at)
                )

    def get_trust_rules(self, user_id: str) -> dict | None:
        placeholder = "%s" if self.is_postgres else "?"
        import json
        with self._db() as conn:
            try:
                if not self.is_postgres:
                    conn.row_factory = sqlite3.Row
                row = conn.execute(f"SELECT * FROM trust_rules WHERE user_id = {placeholder}", (user_id,)).fetchone()
                if not row:
                    return None
                d = dict(row)
                d['auto_trust_contacts'] = bool(d.get('auto_trust_contacts', 0))
                d['whitelist'] = json.loads(d.get('whitelist', '[]'))
                d['blacklist'] = json.loads(d.get('blacklist', '[]'))
                return d
            except Exception:
                return None

    def set_scan_feedback(self, scan_id: str, user_id: str, feedback: str, note: str) -> dict | None:
        placeholder = "%s" if self.is_postgres else "?"
        updated_at = datetime.now(timezone.utc).isoformat()
        import json
        with self._db() as conn:
            if not self.is_postgres:
                conn.row_factory = sqlite3.Row
            row = conn.execute(f"SELECT evidence_json FROM scans WHERE id = {placeholder} AND user_id = {placeholder}", (scan_id, user_id)).fetchone()
            if not row:
                return None
            
            try:
                evidence = json.loads(row["evidence_json"] if isinstance(row, dict) else row[0])
            except Exception:
                evidence = {}
            
            evidence["review_feedback"] = {
                "feedback": feedback,
                "note": note,
                "updated_at": updated_at
            }
            
            conn.execute(
                f"UPDATE scans SET evidence_json = {placeholder} WHERE id = {placeholder} AND user_id = {placeholder}",
                (json.dumps(evidence), scan_id, user_id)
            )
        return self.get_scan(scan_id, user_id)

