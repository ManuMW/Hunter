"""
Hunter Threat Research - SQLite State Persistence Engine
Provides durable, thread-safe persistence for client daily quotas,
in-flight queue state, and task execution history across reboots.
Adheres to HUN-21.
"""

import json
import logging
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Dict, Any, Optional, List, Tuple

from src.config import BASE_DIR, CLIENT_DAILY_QUOTA

logger = logging.getLogger(__name__)

# Default database file path (persisted in data/ or root)
DATA_DIR = BASE_DIR / "data"
DATA_DIR.mkdir(parents=True, exist_ok=True)
DEFAULT_DB_PATH = DATA_DIR / "hunter.db"


class HunterDatabase:
    def __init__(self, db_path: Optional[Path] = None):
        self.db_path = db_path or DEFAULT_DB_PATH
        self.init_db()

    def _get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path), timeout=15.0)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")
        return conn

    def init_db(self):
        """Initializes tables and indices."""
        with self._get_connection() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS client_quotas (
                    client_id TEXT NOT NULL,
                    date_utc TEXT NOT NULL,
                    detonation_count INTEGER DEFAULT 0,
                    last_submitted_at TEXT NOT NULL,
                    PRIMARY KEY (client_id, date_utc)
                )
            """)

            conn.execute("""
                CREATE TABLE IF NOT EXISTS detonation_tasks (
                    task_id TEXT PRIMARY KEY,
                    sha256 TEXT NOT NULL,
                    filename TEXT,
                    status TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    completed_at TEXT,
                    error TEXT,
                    report_path TEXT,
                    report_data_json TEXT,
                    sample_meta_json TEXT
                )
            """)

            conn.execute("CREATE INDEX IF NOT EXISTS idx_tasks_sha256 ON detonation_tasks (sha256)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_tasks_status ON detonation_tasks (status)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_quotas_date ON client_quotas (date_utc)")
            conn.commit()

    # =========================================================================
    # Client Quotas (Rate Limiting)
    # =========================================================================
    def check_client_quota(self, client_id: str, date_utc: str, daily_limit: int = CLIENT_DAILY_QUOTA) -> Tuple[bool, int, int]:
        """
        Checks remaining quota for a client on the given UTC date.
        Returns: (is_allowed, used_count, remaining_quota)
        """
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT detonation_count FROM client_quotas WHERE client_id = ? AND date_utc = ?",
                (client_id, date_utc)
            )
            row = cursor.fetchone()
            used = row["detonation_count"] if row else 0

        remaining = max(0, daily_limit - used)
        is_allowed = used < daily_limit
        return is_allowed, used, remaining

    def consume_client_quota(self, client_id: str, date_utc: str) -> int:
        """
        Increments client detonation count.
        Returns: new used count
        """
        now_iso = datetime.now(timezone.utc).isoformat()
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO client_quotas (client_id, date_utc, detonation_count, last_submitted_at)
                VALUES (?, ?, 1, ?)
                ON CONFLICT(client_id, date_utc) DO UPDATE SET
                    detonation_count = detonation_count + 1,
                    last_submitted_at = excluded.last_submitted_at
            """, (client_id, date_utc, now_iso))
            conn.commit()

            cursor.execute(
                "SELECT detonation_count FROM client_quotas WHERE client_id = ? AND date_utc = ?",
                (client_id, date_utc)
            )
            return cursor.fetchone()["detonation_count"]

    # =========================================================================
    # Task Lifecycle & Recovery
    # =========================================================================
    def save_task(self, task_dict: Dict[str, Any]):
        """Inserts or updates a detonation task record."""
        sample_meta_json = json.dumps(task_dict.get("sample_meta") or {})
        report_data_json = json.dumps(task_dict.get("report_data") or {}) if task_dict.get("report_data") else None

        with self._get_connection() as conn:
            conn.execute("""
                INSERT INTO detonation_tasks (
                    task_id, sha256, filename, status, created_at,
                    completed_at, error, report_path, report_data_json, sample_meta_json
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(task_id) DO UPDATE SET
                    status = excluded.status,
                    completed_at = excluded.completed_at,
                    error = excluded.error,
                    report_path = excluded.report_path,
                    report_data_json = coalesce(excluded.report_data_json, detonation_tasks.report_data_json)
            """, (
                task_dict["task_id"],
                task_dict["sha256"],
                task_dict.get("filename"),
                task_dict.get("status", "queued"),
                task_dict.get("created_at") or datetime.now(timezone.utc).isoformat(),
                task_dict.get("completed_at"),
                task_dict.get("error"),
                task_dict.get("report_path"),
                report_data_json,
                sample_meta_json
            ))
            conn.commit()

    def update_task_status(
        self,
        task_id: str,
        status: str,
        error: Optional[str] = None,
        completed_at: Optional[str] = None,
        report_path: Optional[str] = None,
        report_data: Optional[Dict[str, Any]] = None
    ):
        """Updates the status and metadata of an existing task."""
        report_data_json = json.dumps(report_data) if report_data else None
        with self._get_connection() as conn:
            conn.execute("""
                UPDATE detonation_tasks
                SET status = ?,
                    error = coalesce(?, error),
                    completed_at = coalesce(?, completed_at),
                    report_path = coalesce(?, report_path),
                    report_data_json = coalesce(?, report_data_json)
                WHERE task_id = ?
            """, (status, error, completed_at, report_path, report_data_json, task_id))
            conn.commit()

    def get_task(self, task_id: str) -> Optional[Dict[str, Any]]:
        """Retrieves a task by task_id."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM detonation_tasks WHERE task_id = ?", (task_id,))
            row = cursor.fetchone()
            if not row:
                return None
            return self._row_to_task_dict(row)

    def get_task_by_sha256(self, sha256: str) -> Optional[Dict[str, Any]]:
        """Retrieves the latest task for a given sha256."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT * FROM detonation_tasks WHERE sha256 = ? ORDER BY created_at DESC LIMIT 1",
                (sha256.lower().strip(),)
            )
            row = cursor.fetchone()
            if not row:
                return None
            return self._row_to_task_dict(row)

    def list_recent_tasks(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Lists recent tasks ordered by creation time."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT * FROM detonation_tasks ORDER BY created_at DESC LIMIT ?",
                (limit,)
            )
            return [self._row_to_task_dict(row) for row in cursor.fetchall()]

    def recover_interrupted_tasks(self) -> int:
        """
        Marks any tasks left in non-terminal states ('queued', 'detonating', 'analyzing', etc.)
        from a previous abnormal shutdown as 'failed'.
        Returns count of recovered tasks.
        """
        now_iso = datetime.now(timezone.utc).isoformat()
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                UPDATE detonation_tasks
                SET status = 'failed',
                    error = 'Task aborted due to system restart or host shutdown.',
                    completed_at = ?
                WHERE status IN ('queued', 'detonating', 'extracting_artifacts', 'analyzing', 'generating_report')
            """, (now_iso,))
            conn.commit()
            count = cursor.rowcount
            if count > 0:
                logger.warning(f"[*] Recovered {count} interrupted tasks on startup.")
            return count

    def prune_expired_records(self, retention_days: int = 7) -> int:
        """
        Removes quota records and task history older than retention_days.
        Returns total number of deleted rows.
        """
        cutoff_date = (datetime.now(timezone.utc) - timedelta(days=retention_days)).strftime("%Y-%m-%d")
        cutoff_iso = (datetime.now(timezone.utc) - timedelta(days=retention_days)).isoformat()

        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM client_quotas WHERE date_utc < ?", (cutoff_date,))
            quotas_deleted = cursor.rowcount

            cursor.execute("DELETE FROM detonation_tasks WHERE created_at < ? AND status IN ('completed', 'failed')", (cutoff_iso,))
            tasks_deleted = cursor.rowcount

            conn.commit()
            total = quotas_deleted + tasks_deleted
            if total > 0:
                logger.info(f"[*] Pruned {total} expired records older than {retention_days} days ({quotas_deleted} quotas, {tasks_deleted} tasks).")
            return total

    def _row_to_task_dict(self, row: sqlite3.Row) -> Dict[str, Any]:
        report_data = None
        if row["report_data_json"]:
            try:
                report_data = json.loads(row["report_data_json"])
            except Exception:
                pass

        sample_meta = {}
        if row["sample_meta_json"]:
            try:
                sample_meta = json.loads(row["sample_meta_json"])
            except Exception:
                pass

        return {
            "task_id": row["task_id"],
            "sha256": row["sha256"],
            "filename": row["filename"],
            "status": row["status"],
            "created_at": row["created_at"],
            "completed_at": row["completed_at"],
            "error": row["error"],
            "report_path": row["report_path"],
            "report_data": report_data,
            "sample_meta": sample_meta
        }


# Global Singleton Database Instance
db = HunterDatabase()
