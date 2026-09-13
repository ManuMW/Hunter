import logging
import sqlite3
from datetime import datetime, timezone
from typing import Tuple, Optional

import httpx

from src.config import DATABASE_PATH, CLIENT_DAILY_QUOTA, TURNSTILE_SECRET_KEY

logger = logging.getLogger(__name__)


def init_db():
    """Initializes the SQLite rate-limiting table."""
    with sqlite3.connect(DATABASE_PATH) as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS client_quotas (
                client_id TEXT NOT NULL,
                date_utc TEXT NOT NULL,
                detonation_count INTEGER DEFAULT 0,
                PRIMARY KEY (client_id, date_utc)
            )
        """)
        conn.commit()


# Initialize database on module load
init_db()


def get_today_utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d")


def build_client_identifier(ip: str, browser_uuid: Optional[str] = None) -> str:
    """Builds a composite client identifier combining IP and browser UUID if present."""
    clean_ip = ip.strip()
    if browser_uuid and browser_uuid.strip():
        return f"{clean_ip}:{browser_uuid.strip()}"
    return clean_ip


def check_client_quota(client_id: str) -> Tuple[bool, int, int]:
    """
    Checks if a client has remaining quota for today (UTC).
    Returns (is_allowed, current_count, remaining_quota).
    """
    today = get_today_utc()
    with sqlite3.connect(DATABASE_PATH) as conn:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT detonation_count FROM client_quotas WHERE client_id = ? AND date_utc = ?",
            (client_id, today)
        )
        row = cursor.fetchone()
        used = row[0] if row else 0

    remaining = max(0, CLIENT_DAILY_QUOTA - used)
    is_allowed = used < CLIENT_DAILY_QUOTA
    return is_allowed, used, remaining


def consume_client_quota(client_id: str) -> int:
    """
    Increments the client's detonation count for today.
    Returns the new used count.
    """
    today = get_today_utc()
    with sqlite3.connect(DATABASE_PATH) as conn:
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO client_quotas (client_id, date_utc, detonation_count)
            VALUES (?, ?, 1)
            ON CONFLICT(client_id, date_utc) DO UPDATE SET detonation_count = detonation_count + 1
        """, (client_id, today))
        conn.commit()

        cursor.execute(
            "SELECT detonation_count FROM client_quotas WHERE client_id = ? AND date_utc = ?",
            (client_id, today)
        )
        return cursor.fetchone()[0]


def verify_turnstile_token(token: Optional[str], client_ip: str) -> bool:
    """
    Verifies Cloudflare Turnstile CAPTCHA token if TURNSTILE_SECRET_KEY is configured.
    If secret key is empty, verification is bypassed (for local testing/development).
    """
    if not TURNSTILE_SECRET_KEY:
        return True

    if not token:
        logger.warning(f"Turnstile token missing from client {client_ip}")
        return False

    try:
        with httpx.Client(timeout=5.0) as client:
            resp = client.post(
                "https://challenges.cloudflare.com/turnstile/v0/siteverify",
                data={
                    "secret": TURNSTILE_SECRET_KEY,
                    "response": token,
                    "remoteip": client_ip
                }
            )
            data = resp.json()
            return bool(data.get("success"))
    except Exception as e:
        logger.error(f"Failed to verify Turnstile token: {e}")
        return False
